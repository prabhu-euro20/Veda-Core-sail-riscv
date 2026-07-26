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
function ext_reset() -> unit = veda_test_seed_odt()
