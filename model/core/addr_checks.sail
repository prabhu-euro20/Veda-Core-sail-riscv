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


// The default data address function does not perform any checks so
// just uses unit for error type.
type ext_data_addr_error = unit

// Default data addr is just base register + immediate offset (may be zero).
// Extensions might override and add additional checks.
function ext_data_get_addr(base : regidx, offset : xlenbits, _access : MemoryAccessType(mem_payload), _width : mem_access_width)
         -> Ext_DataAddr_Check(ext_data_addr_error) =
  let addr = Virtaddr(X(base) + offset) in
  Ext_DataAddr_OK(addr)

function ext_handle_data_check_error(_err : ext_data_addr_error) -> unit =
  ()
