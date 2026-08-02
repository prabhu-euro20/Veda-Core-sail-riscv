#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "riscv_callbacks_gdbstub.h"

enum class gdb_prestep_t {
  GDB_prestep_continue, // don't step this iteration, loop again
  GDB_prestep_ok,       // proceed with a real Sail step this iteration
  GDB_prestep_eof,      // client disconnected or program finished; end run
};

// A minimal GDB Remote Serial Protocol (RSP) server for sail_riscv_sim,
// modeled structurally on rvfi_handler (same real, proven TCP setup
// pattern) but implementing the actual interactive RSP command set
// (register/memory read, step, continue, breakpoints) rather than
// RVFI-DII's instruction-injection protocol, which was verified this
// session (full read of rvfi_dii.cpp/.h) to not expose what a live
// debugger session needs.
class gdb_handler {
public:
  explicit gdb_handler(int port, class ModelImpl &model, std::shared_ptr<gdb_stub_callbacks> cb);

  bool setup_socket(bool config_print);
  gdb_prestep_t pre_step(bool config_print);

private:
  enum class State { WaitingForCommand, StepPending, Running };

  // Low-level RSP packet I/O.
  bool read_byte_blocking(uint8_t &out);
  bool try_read_byte_nonblocking(uint8_t &out);
  bool read_packet_blocking(std::string &out);
  void send_packet(const std::string &data);
  void send_ack(bool positive);

  // Command handling.
  void dispatch_immediate(const std::string &packet);
  std::string handle_read_registers();
  std::string handle_read_memory(const std::string &args);
  std::string handle_write_memory(const std::string &args);
  void handle_insert_breakpoint(const std::string &args);
  void handle_remove_breakpoint(const std::string &args);
  void handle_qxfer(const std::string &args);
  static std::string build_target_description_xml();

  int m_port;
  int m_sock = -1;
  class ModelImpl &m_model;
  std::shared_ptr<gdb_stub_callbacks> m_cb;
  State m_state = State::WaitingForCommand;
};
