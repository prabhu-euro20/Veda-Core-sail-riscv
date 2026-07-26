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
  veda_test_seed_odt();
  veda_pcc_base = zeros();
  veda_pcc_length = VEDA_PCC_UNBOUNDED;
  veda_mepcc_base = zeros();
  veda_mepcc_length = VEDA_PCC_UNBOUNDED;
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
  veda_pcc_save_and_reset();
  handle_exception(zero_extend(0b10000 @ 0b00001), E_Extension(()))
}
