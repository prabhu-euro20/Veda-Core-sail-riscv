#include "riscv_callbacks_gdbstub.h"

#include "riscv_model_impl.h"

void gdb_stub_callbacks::xreg_full_write_callback(
  ModelImpl &, const_sail_string, sbits reg, sbits value
) {
  int64_t index = reg.bits;
  if (index >= 1 && index < NUM_GPRS) {
    m_gprs[static_cast<size_t>(index)] = static_cast<uint64_t>(value.bits);
  }
}

void gdb_stub_callbacks::pc_write_callback(ModelImpl &, sbits new_pc) {
  m_pc = static_cast<uint64_t>(new_pc.bits);
  if (m_breakpoints.count(m_pc) != 0) {
    m_breakpoint_hit = true;
  }
}
