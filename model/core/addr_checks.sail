// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// default fetch address checks

type ext_fetch_addr_error = unit

// Since fetch is done in granules, the check function gets two arguments:
// start_pc: the PC at the start of the current fetch sequence
// pc:       the PC for the current granule
//
// returns:  an optional fetch error.
//
// Veda-Core Milestone 14 (rva23-core/veda-core/PCC_COMPARTMENT_DESIGN.md):
// the real *bodies* of these two functions now live in
// postlude/step_ext.sail instead of here, because they need to
// reference Veda's own `veda_pcc_base`/`veda_pcc_length` registers --
// confirmed via a real, direct build failure ("Identifier
// veda_pcc_length is unbound") that `core` is elaborated strictly
// before `Veda_insts` in riscv.sail_project's own module graph (`Veda {
// requires core }`, not the reverse), so a `core`-resident function body
// can never see a Veda-defined register, no matter where in the file
// it's textually written. `postlude` already `requires ... Veda_insts`
// (confirmed by reading riscv.sail_project directly -- the same real
// reason `ext_reset`'s own Veda-referencing body already lives in
// postlude/step_ext.sail, not here). Only the forward `val` declarations
// stay in `core` (matching every other hook in this file, and not
// themselves referencing anything Veda-specific -- just the ordinary,
// already-core-visible `xlenbits`/`option`/`ext_fetch_addr_error`
// types), so `postlude/fetch.sail`'s own calls to these two functions
// (compiled as part of `core`-and-earlier-visible code) still resolve.
val ext_fetch_check_pc : (xlenbits, xlenbits) -> option(ext_fetch_addr_error)

val ext_handle_fetch_check_error : ext_fetch_addr_error -> unit

// default control address checks

type ext_control_addr_error = unit

// This function returns an optional exception for the address to use
// as the target for the control transfer. The control address is
// derived from the PC register, e.g. in JAL.
//
// NOTE: the input value does *not* have bit[0] set to 0, to enable
// more accurate bounds checking.

function ext_control_check_pc(_pc : xlenbits) -> option(ext_control_addr_error) =
  None()

function ext_handle_control_check_error(_err : ext_control_addr_error) -> unit =
  ()


// Veda-Core Milestone 19 (Veda-Purecap Enforcement): widened from a plain
// `unit` to carry a real (cap_idx, cause) payload, mirroring
// veda_xtval's own two-part signature (extensions/Veda/veda_bind_insts.sail)
// exactly, not reinvented -- confirmed safe via a full-codebase grep before
// making this change: the extensions that already propagate this type
// opaquely through `Ext_DataAddr_Check_Failure` (Zaamo, Zicbom, Zicfiss,
// Zicboz, all currently disabled in this project's own test config) never
// construct or pattern-match its internal shape themselves, only ever
// forward whatever `ext_data_get_addr` returned.
struct ext_data_addr_error = {
  cap_idx : bits(5),
  cause   : bits(5),
}

// Veda-Core Milestone 19: the real body now lives in postlude/step_ext.sail,
// for the identical real reason ext_fetch_check_pc's body already does (see
// above) -- it must reference Veda's own `veda_mode`/`veda_pcc_length`
// registers, only visible once `Veda_insts` is required (`postlude`
// requires it, `core` does not, confirmed directly against
// riscv.sail_project, the same real module-ordering constraint already
// documented above ext_fetch_check_pc). Only the forward `val` stays here,
// referencing nothing Veda-specific.
val ext_data_get_addr : (regidx, xlenbits, MemoryAccessType(mem_payload), mem_access_width) -> Ext_DataAddr_Check(ext_data_addr_error)

val ext_handle_data_check_error : ext_data_addr_error -> unit
