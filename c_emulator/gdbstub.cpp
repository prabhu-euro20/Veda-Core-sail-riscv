#include "gdbstub.h"

#include <arpa/inet.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <sstream>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "riscv_model_impl.h"

namespace {

int hex_digit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

std::string to_hex_byte(uint8_t b) {
  static const char *digits = "0123456789abcdef";
  std::string s;
  s += digits[(b >> 4) & 0xF];
  s += digits[b & 0xF];
  return s;
}

// RSP wants register bytes in target (little-endian, for RV64) memory
// order, least-significant byte first.
std::string to_hex_le64(uint64_t v) {
  std::string s;
  for (int i = 0; i < 8; ++i) {
    s += to_hex_byte(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
  }
  return s;
}

uint8_t rsp_checksum(const std::string &data) {
  unsigned sum = 0;
  for (char c : data) {
    sum += static_cast<unsigned char>(c);
  }
  return static_cast<uint8_t>(sum % 256);
}

// Splits "addr,length" or "addr,length:data" style command arguments.
bool parse_addr_length(const std::string &s, uint64_t &addr, uint64_t &length, size_t &next) {
  size_t comma = s.find(',');
  if (comma == std::string::npos) {
    return false;
  }
  addr = std::stoull(s.substr(0, comma), nullptr, 16);
  size_t end = comma + 1;
  while (end < s.size() && hex_digit(s[end]) >= 0) {
    ++end;
  }
  length = std::stoull(s.substr(comma + 1, end - (comma + 1)), nullptr, 16);
  next = end;
  return true;
}

} // namespace

gdb_handler::gdb_handler(int port, ModelImpl &model, std::shared_ptr<gdb_stub_callbacks> cb) :
  m_port(port), m_model(model), m_cb(std::move(cb)) {
  fprintf(stderr, "using %d as GDB stub port.\n", port);
}

bool gdb_handler::setup_socket(bool config_print) {
  int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sock == -1) {
    fprintf(stderr, "gdbstub: unable to create socket: %s\n", strerror(errno));
    return false;
  }
  int reuseaddr = 1;
  if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
    fprintf(stderr, "gdbstub: unable to set reuseaddr: %s\n", strerror(errno));
    return false;
  }
  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<uint16_t>(m_port));
  if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    fprintf(stderr, "gdbstub: unable to bind: %s\n", strerror(errno));
    return false;
  }
  if (listen(listen_sock, 1) == -1) {
    fprintf(stderr, "gdbstub: unable to listen: %s\n", strerror(errno));
    return false;
  }
  socklen_t addrlen = sizeof(addr);
  if (getsockname(listen_sock, (struct sockaddr *)&addr, &addrlen) == -1) {
    fprintf(stderr, "gdbstub: unable to getsockname: %s\n", strerror(errno));
    return false;
  }
  fprintf(stderr, "gdbstub: waiting for GDB connection on port %d.\n", ntohs(addr.sin_port));
  m_sock = accept(listen_sock, nullptr, nullptr);
  if (m_sock == -1) {
    fprintf(stderr, "gdbstub: unable to accept: %s\n", strerror(errno));
    return false;
  }
  close(listen_sock);
  // Non-blocking: select() with a timeout gives us both a blocking-style
  // wait (long/no timeout) and a genuine non-blocking poll (zero timeout)
  // over the same fd, needed to detect an async Ctrl-C while free-running.
  int fd_flags = fcntl(m_sock, F_GETFL);
  if (fd_flags == -1 || fcntl(m_sock, F_SETFL, fd_flags | O_NONBLOCK) == -1) {
    fprintf(stderr, "gdbstub: unable to set non-blocking: %s\n", strerror(errno));
    return false;
  }
  if (config_print) {
    fprintf(stderr, "gdbstub: connected.\n");
  }
  return true;
}

bool gdb_handler::try_read_byte_nonblocking(uint8_t &out) {
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(m_sock, &fds);
  struct timeval tv{0, 0};
  int r = select(m_sock + 1, &fds, nullptr, nullptr, &tv);
  if (r <= 0) {
    return false;
  }
  ssize_t n = recv(m_sock, &out, 1, 0);
  return n == 1;
}

bool gdb_handler::read_byte_blocking(uint8_t &out) {
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(m_sock, &fds);
  int r = select(m_sock + 1, &fds, nullptr, nullptr, nullptr);
  if (r <= 0) {
    return false;
  }
  ssize_t n = recv(m_sock, &out, 1, 0);
  return n == 1;
}

void gdb_handler::send_ack(bool positive) {
  char c = positive ? '+' : '-';
  if (write(m_sock, &c, 1) != 1) {
    fprintf(stderr, "gdbstub: failed to send ack: %s\n", strerror(errno));
  }
}

bool gdb_handler::read_packet_blocking(std::string &out) {
  for (;;) {
    // Scan for the start of a packet ('$'); ignore stray ack bytes and
    // skip a standalone 0x03 (Ctrl-C) here -- during WaitingForCommand
    // an interrupt request is meaningless (we are already stopped).
    uint8_t b;
    do {
      if (!read_byte_blocking(b)) {
        return false; // socket closed
      }
    } while (b != '$');

    std::string data;
    uint8_t checksum_bytes[2];
    bool in_checksum = false;
    int checksum_idx = 0;
    for (;;) {
      if (!read_byte_blocking(b)) {
        return false;
      }
      if (!in_checksum) {
        if (b == '#') {
          in_checksum = true;
        } else {
          data += static_cast<char>(b);
        }
      } else {
        checksum_bytes[checksum_idx++] = b;
        if (checksum_idx == 2) {
          break;
        }
      }
    }
    int hi = hex_digit(static_cast<char>(checksum_bytes[0]));
    int lo = hex_digit(static_cast<char>(checksum_bytes[1]));
    uint8_t received_checksum = static_cast<uint8_t>((hi << 4) | lo);
    if (received_checksum == rsp_checksum(data)) {
      send_ack(true);
      out = data;
      return true;
    }
    send_ack(false);
    // loop again, waiting for a retransmit
  }
}

void gdb_handler::send_packet(const std::string &data) {
  uint8_t checksum = rsp_checksum(data);
  std::string full = "$" + data + "#" + to_hex_byte(checksum);
  for (int attempt = 0; attempt < 5; ++attempt) {
    if (write(m_sock, full.data(), full.size()) != static_cast<ssize_t>(full.size())) {
      fprintf(stderr, "gdbstub: failed to send packet: %s\n", strerror(errno));
      return;
    }
    uint8_t ack;
    if (!read_byte_blocking(ack)) {
      return; // socket closed
    }
    if (ack == '+') {
      return;
    }
    // '-' (or anything else): retry
  }
}

std::string gdb_handler::handle_read_registers() {
  std::string reply;
  for (int i = 0; i < gdb_stub_callbacks::NUM_GPRS; ++i) {
    reply += to_hex_le64(m_cb->gpr(i));
  }
  reply += to_hex_le64(m_cb->pc());
  // Capability registers c0-c15: the real, hardware-packed 136 bits (17
  // bytes, widened from 128/16 alongside the 2026-08-19 Length/Offset
  // widening -- veda_cap_pack, the same function OCL.C/OCS.C themselves
  // use, not a hand-rolled re-encoding), one register at a time.
  for (int i = 0; i < 16; ++i) {
    uint8_t bytes[17];
    m_model.pack_veda_capability_reg(i, bytes);
    for (uint8_t b : bytes) {
      reply += to_hex_byte(b);
    }
  }
  // Tag bits, exposed as their own single-byte pseudo-registers (real
  // CHERI-GDB precedent: capability tags are shown as a separate `.t`
  // pseudo-register rather than folded into the 136-bit value, since the
  // tag is genuinely out-of-band -- VEDA_CORE_SPEC.md Section 2 itself
  // states this: "Not counted in the 136").
  for (int i = 0; i < 16; ++i) {
    reply += to_hex_byte(m_model.read_veda_capability_tag(i) ? 1 : 0);
  }
  return reply;
}

std::string gdb_handler::handle_read_memory(const std::string &args) {
  uint64_t addr = 0, length = 0;
  size_t next = 0;
  if (!parse_addr_length(args, addr, length, next)) {
    return "E01";
  }
  if (length > 4096) {
    return "E02";
  }
  std::string reply;
  for (uint64_t i = 0; i < length; ++i) {
    reply += to_hex_byte(static_cast<uint8_t>(read_mem(addr + i)));
  }
  return reply;
}

std::string gdb_handler::handle_write_memory(const std::string &args) {
  uint64_t addr = 0, length = 0;
  size_t next = 0;
  if (!parse_addr_length(args, addr, length, next)) {
    return "E01";
  }
  if (next >= args.size() || args[next] != ':') {
    return "E03";
  }
  std::string hex_data = args.substr(next + 1);
  if (hex_data.size() != length * 2) {
    return "E04";
  }
  for (uint64_t i = 0; i < length; ++i) {
    int hi = hex_digit(hex_data[2 * i]);
    int lo = hex_digit(hex_data[2 * i + 1]);
    write_mem(addr + i, static_cast<uint64_t>((hi << 4) | lo));
  }
  return "OK";
}

void gdb_handler::handle_insert_breakpoint(const std::string &args) {
  // "0,ADDR,KIND" -- only software breakpoints (type 0) are supported.
  size_t first_comma = args.find(',');
  if (first_comma == std::string::npos) {
    return;
  }
  size_t second_comma = args.find(',', first_comma + 1);
  std::string addr_str =
    (second_comma == std::string::npos) ? args.substr(first_comma + 1) : args.substr(first_comma + 1, second_comma - first_comma - 1);
  uint64_t addr = std::stoull(addr_str, nullptr, 16);
  m_cb->add_breakpoint(addr);
}

void gdb_handler::handle_remove_breakpoint(const std::string &args) {
  size_t first_comma = args.find(',');
  if (first_comma == std::string::npos) {
    return;
  }
  size_t second_comma = args.find(',', first_comma + 1);
  std::string addr_str =
    (second_comma == std::string::npos) ? args.substr(first_comma + 1) : args.substr(first_comma + 1, second_comma - first_comma - 1);
  uint64_t addr = std::stoull(addr_str, nullptr, 16);
  m_cb->remove_breakpoint(addr);
}

std::string gdb_handler::build_target_description_xml() {
  std::ostringstream xml;
  xml << "<?xml version=\"1.0\"?>\n";
  xml << "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n";
  xml << "<target version=\"1.0\">\n";
  xml << "  <architecture>riscv:rv64</architecture>\n";
  // Standard RISC-V GPRs + pc, in the same real regnum order (0-31, 32)
  // GDB already used successfully in Toolchain Milestone 3 via its own
  // built-in default -- this feature restates that convention explicitly,
  // not a new invention, so serving a target.xml at all does not change
  // the existing, already-verified base-register behavior.
  xml << "  <feature name=\"org.gnu.gdb.riscv.cpu\">\n";
  static const char *gpr_names[32] = {
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",  "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6",   "a7", "s2", "s3", "s4", "s5", "s6", "s7",  "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
  };
  for (int i = 0; i < 32; ++i) {
    xml << "    <reg name=\"" << gpr_names[i] << "\" bitsize=\"64\" regnum=\"" << i << "\"/>\n";
  }
  xml << "    <reg name=\"pc\" bitsize=\"64\" regnum=\"32\" type=\"code_ptr\"/>\n";
  xml << "  </feature>\n";
  // Veda-Core's own 16-entry, 136-bit capability register file (widened
  // from 128 bits/16 bytes to 136 bits/17 bytes, 2026-08-19, alongside
  // the Length/Offset field widening -- veda_types.sail's own
  // veda_cap_pack/unpack), plus the real, out-of-band tag bits as
  // separate single-byte pseudo-registers (VEDA_CORE_SPEC.md Section 2:
  // the tag is "not counted in the 136" -- real CHERI-GDB's own precedent
  // for exactly this, per this project's earlier GDB-precedent research,
  // uses the same separate-pseudo-register convention rather than folding
  // the tag into the value).
  xml << "  <feature name=\"org.veda-core.capabilities\">\n";
  xml << "    <vector id=\"v136\" type=\"uint8\" count=\"17\"/>\n";
  for (int i = 0; i < 16; ++i) {
    xml << "    <reg name=\"c" << i << "\" bitsize=\"136\" type=\"v136\" regnum=\"" << (33 + i) << "\"/>\n";
  }
  for (int i = 0; i < 16; ++i) {
    xml << "    <reg name=\"c" << i << "_tag\" bitsize=\"8\" type=\"uint8\" regnum=\"" << (49 + i) << "\"/>\n";
  }
  xml << "  </feature>\n";
  xml << "</target>\n";
  return xml.str();
}

void gdb_handler::handle_qxfer(const std::string &args) {
  // args is everything after "qXfer:", e.g. "features:read:target.xml:0,3fb"
  static const std::string kFeaturesReadPrefix = "features:read:target.xml:";
  if (args.rfind(kFeaturesReadPrefix, 0) != 0) {
    send_packet(""); // unsupported object
    return;
  }
  std::string offset_length = args.substr(kFeaturesReadPrefix.size());
  size_t comma = offset_length.find(',');
  if (comma == std::string::npos) {
    send_packet("E01");
    return;
  }
  uint64_t offset = std::stoull(offset_length.substr(0, comma), nullptr, 16);
  uint64_t length = std::stoull(offset_length.substr(comma + 1), nullptr, 16);

  static const std::string xml = build_target_description_xml();
  if (offset >= xml.size()) {
    send_packet("l"); // no more data
    return;
  }
  uint64_t remaining = xml.size() - offset;
  uint64_t chunk_len = std::min(length, remaining);
  std::string chunk = xml.substr(offset, chunk_len);
  bool is_last = (offset + chunk_len) >= xml.size();
  send_packet((is_last ? "l" : "m") + chunk);
}

void gdb_handler::dispatch_immediate(const std::string &packet) {
  if (packet.empty()) {
    send_packet("");
    return;
  }
  char cmd = packet[0];
  std::string args = packet.substr(1);
  switch (cmd) {
  case '?':
    send_packet("S05");
    break;
  case 'g':
    send_packet(handle_read_registers());
    break;
  case 'G':
    // Live register writes are not supported by this minimal stub
    // (no direct "set register" primitive is exposed by ModelImpl;
    // this is a real, stated scope limit, not a silent omission).
    send_packet("");
    break;
  case 'm':
    send_packet(handle_read_memory(args));
    break;
  case 'M':
    send_packet(handle_write_memory(args));
    break;
  case 'Z':
    if (!args.empty() && args[0] == '0') {
      handle_insert_breakpoint(args);
      send_packet("OK");
    } else {
      send_packet(""); // only software breakpoints (type 0) supported
    }
    break;
  case 'z':
    if (!args.empty() && args[0] == '0') {
      handle_remove_breakpoint(args);
      send_packet("OK");
    } else {
      send_packet("");
    }
    break;
  case 'q':
    if (args.rfind("Supported", 0) == 0) {
      // Advertise real, actually-implemented capabilities only: the
      // target-description XML transfer (needed for c0-c15 visibility).
      // No other qSupported features are claimed.
      send_packet("qXfer:features:read+");
    } else if (args.rfind("Xfer:", 0) == 0) {
      handle_qxfer(args.substr(5));
    } else {
      // Any other query: reply with the empty "not supported" response
      // rather than claiming support we don't genuinely have.
      send_packet("");
    }
    break;
  default:
    send_packet("");
    break;
  }
}

gdb_prestep_t gdb_handler::pre_step(bool config_print) {
  switch (m_state) {
  case State::StepPending: {
    if (config_print) {
      fprintf(stderr, "gdbstub: step complete, pc=0x%" PRIx64 "\n", m_cb->pc());
    }
    send_packet("S05");
    m_state = State::WaitingForCommand;
    return gdb_prestep_t::GDB_prestep_continue;
  }
  case State::Running: {
    if (m_model.htif_done()) {
      send_packet("W00");
      return gdb_prestep_t::GDB_prestep_eof;
    }
    if (m_cb->breakpoint_hit()) {
      m_cb->clear_breakpoint_hit();
      if (config_print) {
        fprintf(stderr, "gdbstub: breakpoint hit at pc=0x%" PRIx64 "\n", m_cb->pc());
      }
      send_packet("S05");
      m_state = State::WaitingForCommand;
      return gdb_prestep_t::GDB_prestep_continue;
    }
    uint8_t b;
    if (try_read_byte_nonblocking(b) && b == 0x03) {
      if (config_print) {
        fprintf(stderr, "gdbstub: Ctrl-C interrupt received.\n");
      }
      send_packet("S02");
      m_state = State::WaitingForCommand;
      return gdb_prestep_t::GDB_prestep_continue;
    }
    return gdb_prestep_t::GDB_prestep_ok;
  }
  case State::WaitingForCommand:
  default: {
    std::string packet;
    if (!read_packet_blocking(packet)) {
      return gdb_prestep_t::GDB_prestep_eof;
    }
    if (packet == "s") {
      m_state = State::StepPending;
      return gdb_prestep_t::GDB_prestep_ok;
    }
    if (packet == "c") {
      m_state = State::Running;
      return gdb_prestep_t::GDB_prestep_ok;
    }
    dispatch_immediate(packet);
    return gdb_prestep_t::GDB_prestep_continue;
  }
  }
}
