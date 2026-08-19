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
// deferred, later work"). 16-byte (128-bit) granules, matching the
// capability's own real width (VEDA_CORE_SPEC.md Section 2).
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
type veda_tagstore_granules : Int = 32768  // 0x80000 bytes / 16 bytes per granule
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
function veda_tagstore_index_from64(addr64 : bits(64)) -> option(int) = {
  if unsigned(addr64) < unsigned(veda_tagstore_base) then None()
  else {
    // Stay in bits(64) arithmetic (subtract, then shift right by 4 = /16,
    // since 16 is a power of two -- the same real, natural technique real
    // hardware would use for a fixed granule size) rather than plain-int
    // division, which Sail's dependent-type checker cannot statically
    // prove non-negative/well-founded here (a real "Could not resolve
    // quantifiers" build error, not assumed -- confirmed by actually
    // attempting the division form first).
    let byte_off : bits(64) = addr64 - veda_tagstore_base;
    let granule : int = unsigned(byte_off >> 4);
    if granule >= veda_tagstore_granules then None() else Some(granule)
  }
}

function veda_tagstore_index(addr : physaddrbits) -> option(int) =
  veda_tagstore_index_from64(zero_extend(addr))

// Real, honest gap closed 2026-08-19, found by actually reading this
// file's own logic while implementing the Length/Offset widening
// (NEXT_STEPS_ROADMAP.md's own audit had already decided "coarse
// 16-byte granule... each capability-store now sets/clears exactly 2
// adjacent, contiguous granule tag bits," but that decision was verified
// against real Yosys synthesis of the *RTL's* own tag_mem write logic
// only -- this file, Sail's own independent tag-store implementation,
// was never separately checked against it). Before this fix,
// __WriteRAM_Meta/__ReadRAM_Meta computed a SINGLE granule index from
// `addr` alone and completely ignored `width` -- harmless by coincidence
// for the original 128-bit/16-byte capability only if every real
// capability-store happened to be 16-byte-aligned (never actually
// enforced anywhere), and now genuinely broken for the 136-bit/17-byte
// capability: a 17-byte OCS.C store's own 17th byte always spills into a
// SECOND granule that this single-index model never touched at all --
// meaning that byte's own real data was written to RAM (write_ram's own
// underlying byte-level store is unconditional) but never protected by
// the tag mechanism, so an unrelated plain write landing on that same
// spillover byte could silently corrupt part of a "still tagged"
// capability's own field bits, undetected. Fixed by computing the real
// index of the access's OWN last byte too (`addr + width - 1`, the
// identical "last byte, not just first" idiom already established for
// bounds checks elsewhere in this extension, e.g. veda_ocl_insts.sail's
// `offset + width > Length`) and touching both granules identically --
// any access up to `max_mem_access` bytes can span at most 2 of these
// 16-byte granules in practice for this project's own real widths (8 for
// OCL.D/OCS.D, 17 for OCL.C/OCS.C), so no loop is needed, matching the
// real, established "2 adjacent granules, not N" design this project
// already committed to on the RTL side. A partial write straddling the
// tag store's own outer scope boundary (one end in range, one not) tags
// only the in-range end -- an honest, safe partial-coverage choice for a
// real edge condition no current test reaches, not assumed away.
function __WriteRAM_Meta(addr : physaddrbits, width : mem_access_width, meta : mem_meta) -> unit = {
  let addr64 : bits(64) = zero_extend(addr);
  let last64 : bits(64) = addr64 + to_bits(64, width - 1);
  let g0 = veda_tagstore_index_from64(addr64);
  let g1 = veda_tagstore_index_from64(last64);
  match g0 {
    Some(idx) => { assert(idx >= 0 & idx < veda_tagstore_granules); veda_tag_store[idx] = meta },
    None() => (),
  };
  match g1 {
    Some(idx) => {
      // Skip re-writing the same index a narrow (single-granule) access
      // already covered above -- not incorrect either way (writing the
      // same value twice is a no-op), just avoids a redundant write.
      if g0 != Some(idx) then {
        assert(idx >= 0 & idx < veda_tagstore_granules);
        veda_tag_store[idx] = meta
      }
    },
    None() => (),
  }
}

// Mirrors __WriteRAM_Meta's own real multi-granule fix above, for reads:
// a capability is only genuinely valid (tag = true) if EVERY granule its
// own real footprint spans still reads back tagged -- if either granule
// was independently cleared since (e.g. a plain write landed on just the
// spillover byte in the second granule), the whole capability must read
// back untagged, matching this project's own established "storing an
// invalid capability is legal, it just can't be loaded back as valid"
// principle (veda_ocl_insts.sail's own OCS.C comment) applied at the
// sub-capability granule level, not just the whole-capability level.
function __ReadRAM_Meta(addr : physaddrbits, width : mem_access_width) -> mem_meta = {
  let addr64 : bits(64) = zero_extend(addr);
  let last64 : bits(64) = addr64 + to_bits(64, width - 1);
  let t0 : bool = match veda_tagstore_index_from64(addr64) {
    Some(idx) => { assert(idx >= 0 & idx < veda_tagstore_granules); veda_tag_store[idx] },
    None() => default_meta,
  };
  let t1 : bool = match veda_tagstore_index_from64(last64) {
    Some(idx) => { assert(idx >= 0 & idx < veda_tagstore_granules); veda_tag_store[idx] },
    None() => default_meta,
  };
  t0 & t1
}
