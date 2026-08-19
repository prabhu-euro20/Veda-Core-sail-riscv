// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// default exception model

type ext_exception = unit

// Is XRET from given mode permitted by extension?
function ext_check_xret_priv (_p : Privilege) : Privilege -> bool = true
// Called if above check fails
function ext_fail_xret_priv () : unit -> unit = ()

// Veda-Core Milestone 21: the real body now lives in
// postlude/step_ext.sail, the identical real reason ext_fetch_check_pc's
// and ext_data_get_addr's bodies already do (needs veda_pcc_length/
// veda_pcc_save_and_reset, only visible once Veda_insts is required --
// Veda_insts itself requires `exceptions`, confirmed directly against
// riscv.sail_project, so a function body living in this file could never
// see a Veda-defined register no matter how it were written). Only the
// forward `val` stays here.
val handle_trap_extension : (Privilege, xlenbits, option(unit)) -> unit

// Same real reason as handle_trap_extension immediately above: needs
// veda_mepcc_base/_length, only visible once Veda_insts is required.
// Called from extensions/I/base_insts.sail's execute MRET()/SRET(),
// which (module I) does not itself require Veda -- only the forward
// `val` lives here; the real body stays in extensions/Veda/veda_regs.sail
// where it was written, resolved once the whole program links.
val veda_pcc_restore_on_xret : unit -> unit

// Same real reason again: needs veda_pcc_length, only visible once
// Veda_insts is required. Called from sys/sys_control.sail's check_CSR
// (the same real function that already calls stateen_allows_CSR_access
// for the identical reason), which does not itself require Veda -- only
// the forward `val` lives here; the real body is in
// extensions/Veda/veda_regs.sail, right after veda_pcc_restore_on_xret.
val veda_allows_CSR_access : (csreg, Privilege, CSRAccessType) -> bool

// LOCAL_FAULT_RECOVERY_DESIGN.md: same real reason as the two forward
// `val`s immediately above -- needs veda_local_handler_redirect_pending/
// _target, only visible once Veda_insts is required. prepare_trap_vector
// below is the one real function, confirmed by direct grep, that every
// trap's actual jump target flows through (sys/sys_control.sail's
// trap_handler, both its Machine and Supervisor arms) -- the correct,
// minimal, single point to let a pending local-handler redirect
// override the ordinary mtvec-computed target, rather than touching
// trap_handler's own two call sites in that other, still-more-base file.
val veda_trap_vector_override : xlenbits -> xlenbits

// used for traps and ECALL
function prepare_trap_vector(p : Privilege, cause : Mcause) -> xlenbits = {
  let tvec : Mtvec = match p {
    Machine           => mtvec,
    Supervisor        => stvec,
    User              => internal_error(__FILE__, __LINE__, "Invalid privilege level"),
    VirtualUser       => internal_error(__FILE__, __LINE__, "Hypervisor extension not supported"),
    VirtualSupervisor => internal_error(__FILE__, __LINE__, "Hypervisor extension not supported"),
  };
  let ordinary_target : xlenbits = match tvec_addr(tvec, cause) {
    Some(epc) => epc,
    None()    => internal_error(__FILE__, __LINE__, "Invalid tvec mode")
  };
  veda_trap_vector_override(ordinary_target)
}

// xRET handling involves three functions:
//
// get_xepc:            used to read the value of the xret target  (no control flow transfer)
// set_xepc:            used to write a value of the xret target   (no control flow transfer)
// prepare_xret_target: used to get the value for control transfer to the xret target

function get_xepc(p : Privilege) -> xlenbits =
  match p {
    Machine           => align_pc(mepc),
    Supervisor        => align_pc(sepc),
    User              => internal_error(__FILE__, __LINE__, "Invalid privilege level"),
    VirtualUser       => internal_error(__FILE__, __LINE__, "Hypervisor extension not supported"),
    VirtualSupervisor => internal_error(__FILE__, __LINE__, "Hypervisor extension not supported"),
  }

function set_xepc(p : Privilege, value : xlenbits) -> xlenbits = {
  let target = legalize_xepc(value);
  match p {
    Machine           => mepc = target,
    Supervisor        => sepc = target,
    User              => internal_error(__FILE__, __LINE__, "Invalid privilege level"),
    VirtualUser       => internal_error(__FILE__, __LINE__, "Hypervisor extension not supported"),
    VirtualSupervisor => internal_error(__FILE__, __LINE__, "Hypervisor extension not supported"),
  };
  target
}

function prepare_xret_target(p : Privilege) -> xlenbits =
  get_xepc(p)

// other trap-related CSRs

function get_mtvec() -> xlenbits =
  mtvec.bits

function get_stvec() -> xlenbits =
  stvec.bits

function set_mtvec(value : xlenbits) -> xlenbits = {
  mtvec = legalize_tvec(mtvec,
                        value,
                        plat_mtvec_direct_mode_supported,
                        plat_mtvec_direct_base_alignment_exp,
                        plat_mtvec_vectored_mode_supported,
                        plat_mtvec_vectored_base_alignment_exp);
  mtvec.bits
}

function set_stvec(value : xlenbits) -> xlenbits = {
  stvec = legalize_tvec(stvec,
                        value,
                        plat_stvec_direct_mode_supported,
                        2,
                        plat_stvec_vectored_mode_supported,
                        plat_stvec_vectored_base_alignment_exp);
  stvec.bits
}

// Ensure that xtvec[Mode] contains a supported value on reset.
// This would matter if these fields are read-only for the DUT.
function reset_tvecs() -> unit = {
  if plat_mtvec_direct_mode_supported then {
    mtvec[Mode] = trapVectorMode(TV_Direct)
  } else if plat_mtvec_vectored_mode_supported then {
    mtvec[Mode] = trapVectorMode(TV_Vector)
  };
  if plat_stvec_direct_mode_supported then {
    stvec[Mode] = trapVectorMode(TV_Direct)
  } else if plat_stvec_vectored_mode_supported then {
    stvec[Mode] = trapVectorMode(TV_Vector)
  };
}

mapping clause csr_name_map = 0x105  <-> "stvec"
mapping clause csr_name_map = 0x141  <-> "sepc"
mapping clause csr_name_map = 0x305  <-> "mtvec"
mapping clause csr_name_map = 0x341  <-> "mepc"

function clause is_CSR_accessible(0x105, _, _) = currentlyEnabled(Ext_S) // stvec
function clause is_CSR_accessible(0x141, _, _) = currentlyEnabled(Ext_S) // sepc
function clause is_CSR_accessible(0x305, _, _) = true // mtvec
function clause is_CSR_accessible(0x341, _, _) = true // mepc

function clause read_CSR(0x105) = get_stvec()
function clause read_CSR(0x141) = get_xepc(Supervisor)
function clause read_CSR(0x305) = get_mtvec()
function clause read_CSR(0x341) = get_xepc(Machine)

function clause write_CSR(0x105, value) = { Ok(set_stvec(value)) }
function clause write_CSR(0x141, value) = { Ok(set_xepc(Supervisor, value)) }
function clause write_CSR(0x305, value) = { Ok(set_mtvec(value)) }
function clause write_CSR(0x341, value) = { Ok(set_xepc(Machine, value)) }
