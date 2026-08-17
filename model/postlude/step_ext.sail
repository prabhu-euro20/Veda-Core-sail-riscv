// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// The default implementation of hooks for the step() and main() functions.

function ext_fetch_hook(f : FetchResult) -> FetchResult = f

function ext_pre_step_hook()  -> unit = ()
function ext_post_step_hook() -> unit = ()

// Veda-Core Milestone V-A: seeds one test ODT entry at reset. Explicitly
// temporary -- FORMAL_VERIFICATION_PLAN.md/VEDA_CORE_SPEC.md Section 5.1
// both flag the real ODT-population instruction/mechanism as "not decided
// this pass"; this lets a hand-written test bind an object and exercise
// OCL.D/OCS.D end-to-end (the Milestone V-A done-criterion) without it.
// To be replaced by a real instruction in Milestone V-B. `ext_reset` is
// this model's own documented extension point ("The default implementation
// of hooks", this file's own header) -- editing it directly here, rather
// than via Sail's scattered-function mechanism, because `ext_reset` is a
// plain (non-scattered) function, confirmed by reading its declaration.
//
// Milestone 14 addition: `veda_pcc_length` must reset to
// `VEDA_PCC_UNBOUNDED`, not Sail's own default zero-initialization --
// left at the default, a length of 0 would make PCC bounds-check every
// single instruction fetch against an empty window starting at address
// 0, hard-trapping on the very first cycle. This is a real correctness
// requirement, not defensive styling: PCC_COMPARTMENT_DESIGN.md's own
// entire "no constraint until OCInvoke narrows it" design depends on
// this exact reset value.
function ext_reset() -> unit = {
  // R24: BEFORE the seeding, never after. The capability register file needs a
  // defined architectural reset -- otype 0xFFFF, not Sail's struct-default zero,
  // which aliases a real seal type and made Rebind into an untouched register
  // behave differently here than on the RTL. veda_test_seed_odt() then writes
  // its fixtures on top, so the order is load-bearing: reversed, the fixtures
  // would be erased and every R10 crossing test would lose its scaffolding.
  veda_reset_crf();
  // R37: the three Special Capability Registers were not in R24's fix and had no
  // reset at all, so they came up sealed with type zero -- including the ODA,
  // whose sealedness gates every ODT-mutating instruction. Same argument, same
  // constant, three registers R24 missed.
  veda_reset_scr();
  veda_test_seed_odt();
  veda_pcc_base = zeros();
  veda_pcc_length = VEDA_PCC_UNBOUNDED;
  veda_mepcc_base = zeros();
  veda_mepcc_length = VEDA_PCC_UNBOUNDED;
  veda_trap_depth = zeros();
  veda_pcc_object = VEDA_OBJECT_NONE;
  veda_mepcc_object = VEDA_OBJECT_NONE;
  veda_trap_poison = false;
  // R10: the saved-CRBR pair resets to its own "nothing saved" sentinel,
  // the exact analogue of the mepcc pair above (region 0 is a legitimate
  // region, so the empty sentinel must be an out-of-window value instead).
  veda_saved_region = VEDA_REGION_NONE;
  veda_saved_region_base = zeros();
  // Milestone 18: explicit zero, matching this function's own existing
  // explicit-reset style above (Sail's own default is already zero).
  veda_attr = zeros();
  // Milestone 19: explicit zero (veda_purecap off by default) -- same
  // reasoning as veda_attr above; a real correctness requirement here
  // too, not defensive styling, since an unintended reset default of
  // "purecap already on" would hard-trap the very first ordinary
  // LOAD/STORE any pre-existing test in this project's own 24-test
  // corpus executes.
  veda_mode = zeros();
}

// Veda-Core Milestone 14 (rva23-core/veda-core/PCC_COMPARTMENT_DESIGN.md):
// the real bodies for the two `val`-only-declared hooks in
// core/addr_checks.sail (moved here because they need Veda's own
// registers, only visible once `Veda_insts` is required -- `postlude`
// itself already requires it, confirmed by reading riscv.sail_project,
// the same real reason `ext_reset` above already lives in this file).
// Implements the fetch-time half of bounding execution inside an
// `OCInvoke`-entered compartment: a real violation (PC outside the live
// `veda_pcc_base`/`veda_pcc_length` window, only ever narrowed away from
// "unbounded" by a successful `OCInvoke`) is reported via `Some(())`,
// dispatched by `ext_handle_fetch_check_error` below.
function ext_fetch_check_pc(_start_pc : xlenbits, pc : xlenbits) -> option(ext_fetch_addr_error) =
  if veda_pcc_length != VEDA_PCC_UNBOUNDED &
     (unsigned(pc) < unsigned(veda_pcc_base) |
      unsigned(pc) >= unsigned(veda_pcc_base) + unsigned(veda_pcc_length))
  then Some(())
  else None()

// Delivers the real trap via `handle_exception` directly -- the same
// real mechanism ordinary base-ISA fetch failures already use
// (this file's own sibling postlude/step.sail: `Step_Fetch_Failure(vaddr,
// e) => handle_exception(bits_of(vaddr), e)`) -- not
// `veda_trap()`/`trap()` (those return `ExecutionResult`, consumed by
// the normal per-instruction execute dispatch, a different, incompatible
// calling context from this fetch-time hook, confirmed by reading
// postlude/step.sail's own `Step_Ext_Fetch_Failure(e) =>
// ext_handle_fetch_check_error(e)` dispatch before writing this).
// `cause = 0b00001` (0x01, Bounds/Length Violation, already active,
// reused rather than inventing a new cause code) with `cap_idx =
// 0b10000` (16 decimal, the "this was PCC, not a real capability
// register" sentinel) mirrors real CHERI's own identical choice
// (`handle_cheri_pcc_exception`'s own real `PCC_IDX = 0x10`,
// CHERI ISA spec, verified directly before choosing this value) -- built
// inline rather than through `veda_trap()`'s own 4-bit-`vcapidx`-typed
// interface, since this was never a real capability-register index.
function ext_handle_fetch_check_error(_err : ext_fetch_addr_error) -> unit = {
  // R12: inline save removed -- the chokepoint now performs it exactly
  // once per trap. handle_exception below reaches trap_handler, which
  // calls handle_trap_extension unconditionally.
  handle_exception(zero_extend(0b10000 @ 0b00001), E_Extension(()))
}

// Veda-Core Milestone 19 (Veda-Purecap Enforcement): the real bodies for
// the two `val`-only-declared hooks in core/addr_checks.sail, moved here
// for the identical real reason ext_fetch_check_pc's body already is
// (needs veda_mode/veda_pcc_length, only visible once Veda_insts is
// required -- postlude itself already requires it).
//
// Closes two real gaps in one hook, both routed through the same
// ordinary-memory-access chokepoint every non-Veda LOAD/STORE/AMO/FP
// -load-store/vector-load-store/CFI-shadow-stack access already funnels
// through (get_transformed_data_addr, sys/vmem_utils.sail, called by both
// vmem_read and vmem_write -- confirmed via full-codebase grep, no other
// consumer of ext_data_get_addr exists):
//
//   1. VEDA_CGETBASE (veda_cap_insts.sail's VEDA_CAPQUERY, VEDA_CGETBASE
//      arm) legitimately extracts a capability's raw Base into an
//      ordinary GPR -- a real, spec-required query, Section 1's own
//      "metadata is always inspectable" principle. Nothing previously
//      stopped that GPR value from then being used as an ordinary
//      LOAD/STORE base with zero capability check at all -- CHERI's own
//      real "hybrid mode" has this exact same property; Veda-Core had no
//      equivalent of CHERI's "purecap mode" to close it until this
//      milestone. `veda_purecap` (CSR 0x7C5 bit 0, veda_regs.sail) is the
//      new global switch.
//
//   2. A gap in Milestone 14's own OCInvoke compartment-bounding:
//      `veda_pcc_length` already bounds instruction FETCH inside an
//      OCInvoke-entered compartment (ext_fetch_check_pc, above), but
//      compartmentalized code could still issue an ordinary LOAD/STORE to
//      read/write memory anywhere -- undermining the isolation
//      OCInvoke/PCC-bounding is meant to provide. Reusing veda_pcc_length
//      here (rather than a second, independent bounds check) closes this
//      for free: any code currently running inside a narrowed compartment
//      (veda_pcc_length != VEDA_PCC_UNBOUNDED) has ordinary data access
//      blocked exactly like ordinary fetch already is.
//
// Deliberately does NOT touch Veda's own OCL.D/OCS.D/OCL.C/OCS.C/
// NMC_ADD/Veda-Atomic -- all 8 real call sites use read_ram/write_ram
// directly (core/phys_mem_interface.sail), never vmem_read/vmem_write,
// confirmed via exhaustive grep (the only callers of read_ram/write_ram
// anywhere in this model tree besides the definition itself are these 8
// Veda call sites) -- so this hook is architecturally unreachable from
// any legitimate Veda capability-checked access, by construction, not by
// convention.
function ext_data_get_addr(base : regidx, offset : xlenbits, _access : MemoryAccessType(mem_payload), _width : mem_access_width)
         -> Ext_DataAddr_Check(ext_data_addr_error) =
  if veda_mode[0..0] == 0b1 then
    Ext_DataAddr_Error(struct { cap_idx = 0b10001, cause = VEDA_CAUSE_PURECAP_VIOLATION })
  else if veda_pcc_length != VEDA_PCC_UNBOUNDED then
    Ext_DataAddr_Error(struct { cap_idx = 0b10001, cause = VEDA_CAUSE_PURECAP_VIOLATION })
  else
    let addr = Virtaddr(X(base) + offset) in
    Ext_DataAddr_OK(addr)

// Delivers the real trap via handle_exception directly, the same real
// mechanism ext_handle_fetch_check_error above already uses (confirmed by
// reading postlude/step.sail's own dispatch in full before writing this:
// `Step_Execute(Ext_DataAddr_Check_Failure(e), _) =>
// ext_handle_data_check_error(e)` is reached through execute()'s ordinary
// ExecutionResult/Err(...) path -- a different call shape from the direct
// Step_Ext_Fetch_Failure(e) path above, but ext_handle_data_check_error's
// own declared return type (unit) makes this side-effecting call exactly
// as safe here as it already is above).
//
// cap_idx = 0b10001 (17 decimal): the next sentinel value after PCC's own
// 16 (ext_handle_fetch_check_error, above) -- genuinely outside the real
// 0-15 vcapidx range (veda_types.sail: `newtype vcapidx = Vcapidx :
// bits(4)`), confirmed via grep of this whole extension directory that no
// other planned or existing use of 17 exists. cause =
// VEDA_CAUSE_PURECAP_VIOLATION (0x07) -- a genuinely new cause code, not a
// reuse of 0x01 the way the PCC-fetch violation above reuses Bounds
// Violation: deliberately different, since this violation is not a bounds
// violation at all (it can fire with veda_pcc_length still fully
// unbounded, whenever veda_purecap alone is set) and VEDA_CORE_SPEC.md
// Section 3 already had 0x07 genuinely reserved for exactly this class of
// distinct violation kind.
function ext_handle_data_check_error(err : ext_data_addr_error) -> unit = {
  // R12: inline save removed -- the chokepoint now performs it exactly
  // once per trap. handle_exception below reaches trap_handler, which
  // calls handle_trap_extension unconditionally.
  handle_exception(zero_extend(err.cap_idx @ err.cause), E_Extension(()))
}

// Veda-Core Milestone 21: closes a real, empirically-confirmed gap found
// while auditing Milestone 20's own fix -- `veda_pcc_save_and_reset()`
// previously had exactly 3 real call sites (`veda_trap()`,
// `ext_handle_fetch_check_error`, `ext_handle_data_check_error` above),
// all Veda-specific. An *ordinary*, non-Veda RISC-V exception (`ecall`,
// illegal instruction, misaligned access) taken from inside a live
// OCInvoke compartment never reset `veda_pcc_base`/`_length` at all --
// confirmed via a real PoC run under sail_riscv_sim before this fix: a
// realistic system-service handler placed outside the compartment (the
// normal, expected place for one), reached via an ordinary `ecall`,
// never got fetched at all -- `postlude/fetch.sail`'s own `fetch()`
// unconditionally calls `ext_fetch_check_pc(PC, PC)` for every single
// instruction fetch, confirmed by reading it directly ("assumes the
// external fetch checks are higher priority than the following
// alignment check"), including the very first fetch of a trap handler
// reached via `mtvec`. Since `veda_pcc_length` was still narrowed to the
// original compartment's own bounds, that first fetch itself
// hard-faulted, redirecting back to the same `mtvec` handler, which
// faulted again -- a genuine infinite fault loop, confirmed by running
// the PoC with `--inst-limit 200` and observing it never complete. This
// is not a niche edge case: it is the ordinary, expected way any real
// software makes a system call or takes a fault, completely broken for
// any code ever entered via `OCInvoke`.
//
// Fixed at the one real, universal chokepoint every trap already passes
// through regardless of source -- `handle_trap_extension`
// (exceptions/sys_exceptions.sail's own real, pre-existing, previously
// -unclaimed extension hook, confirmed via grep to be called exactly
// once, unconditionally, from `sys/sys_control.sail`'s own
// `trap_handler()`, for every Machine-delegated exception AND interrupt
// alike -- the only real privilege-delegation path in this project's own
// test config, S/U-mode being disabled). Called after `mepc`/`mcause`/
// `mtval` are already set but before the trap-vector target is computed
// and jumped to -- confirmed by reading `trap_handler`'s own real body in
// full before relying on this ordering -- so by the time the handler's
// own first instruction is fetched, `veda_pcc_length` has already been
// reset, closing the infinite-loop gap directly at its root cause rather
// than patching each individual ordinary-exception call site one by one
// (the same piecemeal, enumerate-every-case approach that created this
// gap in the first place -- Milestone 14/19's own hooks were each
// narrowly scoped to their own specific trigger, never intended to be
// exhaustive over every possible trap source).
//
// Conditional on `veda_pcc_length != VEDA_PCC_UNBOUNDED` (matching this
// file's own established style for every other new check in this
// milestone series) rather than calling `veda_pcc_save_and_reset()`
// unconditionally on every trap -- the overwhelming majority of traps in
// this project's own real test corpus occur outside any compartment, and
// there is no real reason to touch `veda_mepcc_base`/`_length` (whose own
// stated purpose is specifically "the compartment bounds live at trap
// time") when no compartment was ever active to begin with.
//
// Interrupts (`handle_interrupt`, `sys/sys_control.sail`) route through
// this identical `trap_handler()` body and are therefore covered by this
// same fix -- noted honestly as unverified by a real test in this
// project's own test config, since no real interrupt source is currently
// active here (no CLINT/timer wiring exists in this project's own RTL or
// Sail work, per this project's own prior research).
function handle_trap_extension(_p : Privilege, _pc : xlenbits, _ext : option(unit)) -> unit = {
  // R10: the guard gains a second disjunct. "In a compartment" and "in a
  // non-root domain" are INDEPENDENT conditions -- OCInvoke into a
  // max-length (unbounded) code object whose Object_ID names a non-zero
  // region leaves PCC unbounded while the CRBR names that region. A trap
  // taken from that state must still save/reset the CRBR, or the handler
  // would run in the faulting domain (the R10 second escape path). Inside
  // the body, each half stays individually guarded: mepcc's capture of an
  // UNBOUNDED length is its own "nothing saved" sentinel (harmless), and
  // the CRBR capture is conditional on region != 0, so neither half
  // pollutes the other's saved state.
  // R12: the guard is REMOVED and the call is unconditional.
  //
  // It was a LIVE-STATE test ("is a compartment active, so is there
  // context worth saving?"), which is a sound question -- but a counter
  // must count EVERY trap or it is not a trap depth. Under the old guard a
  // nested trap taken from an unbounded handler was invisible: the live
  // state had already been reset by the outer trap, so the guard read
  // false and the nesting was never observed at all. That is precisely the
  // case the mechanism exists to catch.
  //
  // The live-state question has not been discarded, only moved inside
  // veda_pcc_save_and_reset, where it now decides whether the level being
  // entered carries real context (and therefore poisons) rather than
  // whether the trap is counted.
  //
  // Safe to make unconditional only because the eight inline save sites
  // were removed in this same change. sys_control calls this exactly once
  // per delivered trap, in both the Machine and Supervisor arms, before
  // prepare_trap_vector -- so depth tracks traps one-for-one.
  veda_pcc_save_and_reset()
}
