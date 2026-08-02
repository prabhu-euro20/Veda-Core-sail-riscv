#pragma once

#include <array>
#include <cstdint>
#include <set>

#include "riscv_callbacks_if.h"
#include "sail.h"

// Shadow-tracks GPR/PC state (via the Sail model's own write callbacks --
// there is no direct "read register N now" getter on ModelImpl, only
// write-notification hooks, so a live shadow copy is the correct, real
// mechanism, not a workaround) and multi-address software breakpoints
// (a direct generalization of stop_at_pc_callbacks's own single-address
// pc_write_callback pattern to a settable set, for GDB's Z0/z0 commands).
class gdb_stub_callbacks : public callbacks_if {
public:
  static constexpr int NUM_GPRS = 32;

  void xreg_full_write_callback(ModelImpl &model, const_sail_string abi_name, sbits reg, sbits value) override;
  void pc_write_callback(ModelImpl &model, sbits new_pc) override;

  uint64_t gpr(int index) const {
    return (index == 0) ? 0 : m_gprs[static_cast<size_t>(index)];
  }
  uint64_t pc() const {
    return m_pc;
  }

  // pc_write_callback only fires once an instruction actually retires,
  // so the shadow PC would otherwise read 0 (not the real entry point)
  // if GDB inspects state before the very first step -- called once,
  // right after init_model() computes the real entry address.
  void set_initial_pc(uint64_t entry) {
    m_pc = entry;
  }

  void add_breakpoint(uint64_t addr) {
    m_breakpoints.insert(addr);
  }
  void remove_breakpoint(uint64_t addr) {
    m_breakpoints.erase(addr);
  }

  // True exactly once, the step after a breakpoint address was reached;
  // cleared by the caller (gdb_handler) after it is consumed.
  bool breakpoint_hit() const {
    return m_breakpoint_hit;
  }
  void clear_breakpoint_hit() {
    m_breakpoint_hit = false;
  }

private:
  std::array<uint64_t, NUM_GPRS> m_gprs{};
  uint64_t m_pc = 0;
  std::set<uint64_t> m_breakpoints;
  bool m_breakpoint_hit = false;
};
