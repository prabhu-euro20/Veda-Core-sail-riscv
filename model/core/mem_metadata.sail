// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// The default metadata carries no information, and is implemented
// using a unit type -- overridden below by Veda-Core's own real,
// out-of-band capability Tag bit (VEDA_CORE_SPEC.md's OCL.C/OCS.C
// semantics, Milestone 7), following exactly the extension point this
// file's own original comment already named ("specifically for an
// extension to override with real per-location metadata").
//
// mem_meta is redefined from unit to bool: `false` (= default_meta) for
// every ordinary, non-Veda memory access -- base RV64I code (model/sys/
// mem.sail) already threads default_meta through every plain load/store
// unconditionally, so this change is transparent to it; base ISA
// semantics are unaffected, only the *type* default_meta now carries
// changes, not how or when base code uses it.
//
// Real, bounded tag store, mirroring CHERI's own actual hardware
// mechanism (a physically separate tag bit per capability-aligned
// memory granule, set/checked only by capability load/store, never by
// plain data loads/stores) -- not a per-address dictionary over the full
// 64-bit space, which Sail has no native sparse-map primitive for and
// which no real hardware implements unbounded either. Scoped to the same
// real, ELF-loadable RAM region already used throughout this project
// (`rtl/veda_core.tlv`'s own ELFMEM_BASE=0x8000_0000/ELFMEM_SIZE=0x80000),
// an honest, stated scope boundary matching the identical discipline
// already used for the RTL ODT's own 256-entry (not 8.4M-entry) scope
// (`rtl/MILESTONE_PLAN.md`: "real silicon-area consciousness... explicitly
// deferred, later work").
//
// 32-byte (256-bit) granules as of the Phase 1 increment 2 respec
// (DESIGN_01 decision 1), matching the capability's own real width. The
// granule tracks the capability width DELIBERATELY, not incidentally: the
// tag is read as a single bit at the access's own granule, so if one
// capability spanned two granules, a plain store could rewrite its second
// half -- the half holding Perms, otype and generation -- while the tag the
// load actually checks still read 1. That is a permission/generation
// forgery primitive, so "one capability occupies exactly one granule" is a
// security invariant rather than a convenience, and it is what makes the
// 32-byte natural-alignment requirement on OCL.C/OCS.C load-bearing rather
// than decorative. Region coverage is unchanged: 16384 x 32 = 0x80000.
type mem_meta = bool

let default_meta : mem_meta = false

let veda_tagstore_base   : bits(64) = 0x0000000080000000
// A real Kind-Int constant (matching prelude.sail's own `type
// max_mem_access : Int = 4096` idiom, not a plain `let`-bound `int`) --
// needed so the type-checker can actually resolve the vector-index bounds
// proof below at compile time; a plain-int `let` binding doesn't carry
// that compile-time-constant guarantee, a real "Failed to prove
// constraint" build error with the `let` form, confirmed by attempting it
// first.
type veda_tagstore_granules : Int = 16384  // 0x80000 bytes / 32 bytes per granule
// Same real idiom already used in this codebase (core/xlen.sail: `let
// xlen = sizeof(xlen)`) for pulling a Kind-Int constant into value-level
// int expressions -- a bare type-level identifier isn't usable directly
// in value position (a real "Identifier ... is unbound" build error,
// confirmed by attempting it first).
let veda_tagstore_granules = sizeof(veda_tagstore_granules)

register veda_tag_store : vector(veda_tagstore_granules, bool) = vector_init(false)

// Out-of-bounds (outside the modeled RAM region) always reads/writes as
// untagged -- the honest, safe default for an address this tag store was
// never scoped to cover, not a silent assumption of "tagged."
function veda_tagstore_index(addr : physaddrbits) -> option(int) = {
  let addr64 : bits(64) = zero_extend(addr);
  if unsigned(addr64) < unsigned(veda_tagstore_base) then None()
  else {
    // Stay in bits(64) arithmetic (subtract, then shift right by 5 = /32,
    // since 32 is a power of two -- the same real, natural technique real
    // hardware would use for a fixed granule size) rather than plain-int
    // division, which Sail's dependent-type checker cannot statically
    // prove non-negative/well-founded here (a real "Could not resolve
    // quantifiers" build error, not assumed -- confirmed by actually
    // attempting the division form first).
    let byte_off : bits(64) = addr64 - veda_tagstore_base;
    let granule : int = unsigned(byte_off >> 5);
    if granule >= veda_tagstore_granules then None() else Some(granule)
  }
}

function __WriteRAM_Meta(addr : physaddrbits, _width : mem_access_width, meta : mem_meta) -> unit = {
  match veda_tagstore_index(addr) {
    Some(idx) => {
      // veda_tagstore_index's own `if granule >= veda_tagstore_granules
      // then None()` check already guarantees this at the call site, but
      // that fact doesn't survive across the Option boundary to Sail's
      // static type-checker (a real "Failed to prove constraint" build
      // error, confirmed by actually attempting the indexing without this
      // assert first) -- re-asserted here, at the one real point it's
      // needed, rather than trying to thread a refined int type through
      // the Option itself.
      assert(idx >= 0 & idx < veda_tagstore_granules);
      veda_tag_store[idx] = meta
    },
    None() => (),
  }
}

function __ReadRAM_Meta(addr : physaddrbits, _width : mem_access_width) -> mem_meta = {
  match veda_tagstore_index(addr) {
    Some(idx) => {
      assert(idx >= 0 & idx < veda_tagstore_granules);
      veda_tag_store[idx]
    },
    None() => default_meta,
  }
}
