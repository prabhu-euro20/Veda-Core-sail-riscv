// Veda-Core formal model: Capability Register File, Tag array, ODT.
//
// Register-per-index declarations and the match-based rC/wC accessor
// pattern directly follow core/regs.sail's own real rX/wX convention for
// the RV64I GPR file (read in full before writing this file), the closest
// real precedent in this codebase for "a small register file with
// explicit per-index registers and a match-based accessor."

register cr0  : capability
register cr1  : capability
register cr2  : capability
register cr3  : capability
register cr4  : capability
register cr5  : capability
register cr6  : capability
register cr7  : capability
register cr8  : capability
register cr9  : capability
register cr10 : capability
register cr11 : capability
register cr12 : capability
register cr13 : capability
register cr14 : capability
register cr15 : capability

// Tag is out-of-band (VEDA_CORE_SPEC.md Section 2: "Not counted in the
// 128"), so it is modeled as separate parallel state, one bit per
// capability register, rather than folded into the `capability` struct.
register crTags : bits(16)

// Milestone 11: the ODA (Object Descriptor Authority) -- Veda-Core's own
// single Special Capability Register, term-for-term adapted from real
// CHERI's own SCR model (CHERI ISA spec §4.3.6, Table 4.3). Real CHERI
// has many SCRs (PCC/DDC/*TCC/*DC/*EPCC); Veda-Core has exactly one, so
// no SCR-index operand is needed the way real CHERI's `CSpecialRW cd,
// scr, cs1` has -- `OSpecialRW` always targets this one register. Kept
// as its own top-level register (not `cr16`/a 17th CRF entry) since it
// plays a genuinely different architectural role (a capability-authority
// context for privileged instructions, not a general-purpose capability
// register any Object-Bind/OCL/OCS/etc. instruction can target).
register veda_oda : capability
register veda_oda_tag : bool

function rC(Vcapno(r) : vcapno) -> capability = {
  match r {
    0  => cr0,
    1  => cr1,
    2  => cr2,
    3  => cr3,
    4  => cr4,
    5  => cr5,
    6  => cr6,
    7  => cr7,
    8  => cr8,
    9  => cr9,
    10 => cr10,
    11 => cr11,
    12 => cr12,
    13 => cr13,
    14 => cr14,
    15 => cr15,
  }
}

function wC(Vcapno(r) : vcapno, v : capability) -> unit = {
  match r {
    0  => cr0  = v,
    1  => cr1  = v,
    2  => cr2  = v,
    3  => cr3  = v,
    4  => cr4  = v,
    5  => cr5  = v,
    6  => cr6  = v,
    7  => cr7  = v,
    8  => cr8  = v,
    9  => cr9  = v,
    10 => cr10 = v,
    11 => cr11 = v,
    12 => cr12 = v,
    13 => cr13 = v,
    14 => cr14 = v,
    15 => cr15 = v,
  }
}

function rCTag(Vcapno(r) : vcapno) -> bool = crTags[r] == 0b1

function wCTag(Vcapno(r) : vcapno, t : bool) -> unit = {
  crTags = update_subrange_bits(crTags, r, r, if t then 0b1 else 0b0)
}

function rC_bits(Vcapidx(i) : vcapidx) -> capability = rC(Vcapno(unsigned(i)))
function wC_bits(Vcapidx(i) : vcapidx, v : capability) -> unit = wC(Vcapno(unsigned(i)), v)
function rCTag_bits(Vcapidx(i) : vcapidx) -> bool = rCTag(Vcapno(unsigned(i)))
function wCTag_bits(Vcapidx(i) : vcapidx, t : bool) -> unit = wCTag(Vcapno(unsigned(i)), t)

overload C = {rC_bits, wC_bits, rC, wC}
overload CTag = {rCTag_bits, wCTag_bits, rCTag, wCTag}

// The Object Descriptor Table: flat, single-level, system-wide, indexed
// directly by the 23-bit Object_ID (widened from 16 bits this pass --
// VEDA_CORE_SPEC.md Section 2/5.1, veda-core/SCALING_BARRIERS_RESEARCH.md
// Section 3). Real precedent for the `vector(N, T)` register-array idiom:
// pmp/pmp_regs.sail (pmpcfg_n/pmpaddr_n) and sys/vmem_tlb.sail (tlb), both
// read before using this pattern here. 8,388,608 entries is a real,
// substantial jump in absolute table size from the original 65,536 --
// deliberately not glossed over, see VEDA_CORE_SPEC.md Section 5.1's
// updated real memory-footprint arithmetic (~80-100 MiB) and the honest
// note on why the flat design still holds at this width.
register veda_odt : vector(8388608, odt_entry) = vector_init(empty_odt_entry)

function odt_lookup(object_id : bits(23)) -> odt_entry = veda_odt[unsigned(object_id)]

function odt_write(object_id : bits(23), e : odt_entry) -> unit = {
  veda_odt[unsigned(object_id)] = e
}

// Milestone V-A test scaffold, explicitly temporary (see
// postlude/step_ext.sail's ext_reset, which calls this): seeds Object_ID=1
// with a real, valid entry so a hand-written test can Object-Bind it and
// exercise OCL.D/OCS.D end-to-end without a real ODT-population
// instruction (deliberately deferred to Milestone V-B,
// VEDA_CORE_SPEC.md Section 5.1). Base = 0x80010000 -- inside the same RAM
// region ACT4/the RVA23 core's own reset vector uses (0x80000000), offset
// far enough from the ELF entry point to avoid colliding with loaded
// program code/data for a small test binary. Perms = 0x100C: Permit_Load
// (bit 2) + Permit_Store (bit 3), what OCL.D/OCS.D need, **plus
// Permit_NMC_Compute (bit 12), added this pass so the same seeded object
// can also exercise NMC_ADD** -- Milestone V-B, veda_types.sail's bit
// assignment.
function veda_test_seed_odt() -> unit = {
  // 0x0001 was a valid 16-bit literal before this pass's widening; now
  // that odt_write takes bits(23), the literal must be built explicitly
  // (a bare hex literal is sized by its digit count, 4 hex digits = 16
  // bits, which no longer matches) -- same to_bits(width, value) pattern
  // already used in this codebase (veda_types.sail's vcapno_to_vcapidx).
  odt_write(to_bits(23, 1), struct {
    valid      = true,
    Base       = 0x80010000,
    Length     = 0x0040,
    Perms      = 0x100C,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
  });
  // Milestone V-B addition: a second seeded object, deliberately *without*
  // Permit_NMC_Compute (Perms = 0x000C, Load+Store only), so a real
  // negative-control test can confirm NMC_ADD's own new permission gate
  // actually fires rather than assuming it does from the code alone.
  odt_write(to_bits(23, 2), struct {
    valid      = true,
    Base       = 0x80010100,
    Length     = 0x0040,
    Perms      = 0x000C,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
  });
  // Milestone V-B addition: a third seeded object for use as a CSeal/
  // CUnseal type-authority capability -- Perms = 0x300 (Permit_Seal, bit
  // 8, + Permit_Unseal, bit 9, veda_types.sail's bit assignment), Length
  // = 0x10 so small in-range Offset values (used directly as otype) are
  // easy to construct by hand in a test program via OCA.
  odt_write(to_bits(23, 3), struct {
    valid      = true,
    Base       = 0x80010200,
    Length     = 0x0010,
    Perms      = 0x0300,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
  });
  // Milestone V-B addition: a fourth seeded object identical to Object_ID
  // 3 except *without* Permit_Seal/Permit_Unseal, so a real negative test
  // can confirm CSeal/CUnseal's own authorization check actually fires.
  odt_write(to_bits(23, 4), struct {
    valid      = true,
    Base       = 0x80010300,
    Length     = 0x0010,
    Perms      = 0x0000,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
  })
}
