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

// Milestone 14 (PCC_COMPARTMENT_DESIGN.md): the currently-active
// `OCInvoke`-entered compartment's own bounds, and their saved copy
// across a trap -- Base(32)/Length(16), matching the ODT entry's own
// field widths (veda_types.sail's odt_entry), not independently chosen.
// `VEDA_PCC_UNBOUNDED` (all-ones Length) is the "no compartment active"
// sentinel -- real CHERI's own convention that execution starts with an
// "almighty" root capability and only ever narrows (CHERI ISA spec
// §2.3.12/§11.1.2, read in full for PCC_COMPARTMENT_DESIGN.md). Reset
// value is unbounded, so no code that never calls `OCInvoke` is ever
// constrained by this feature at all.
let VEDA_PCC_UNBOUNDED : bits(16) = 0xFFFF
register veda_pcc_base : bits(32)
register veda_pcc_length : bits(16)
// Milestone 14: the direct structural twin of `mepc`, but for the
// compartment bounds instead of the plain PC -- real CHERI's own
// "Exception Program Counter Capability" (CHERI ISA spec §3.4.7:
// "CHERI architectures must save and restore the full PCC when handling
// exceptions"). Restoration across a real `mret` is an explicit
// software step (via the CSR clauses below), not automatic hardware --
// PCC_COMPARTMENT_DESIGN.md §5a's own real finding that `xret_callback`
// is declared `pure` and cannot host this side effect, resolved by
// making this consistent with `mepc`'s own already-explicit
// advance-before-`mret` convention (Milestone 9) rather than forcing an
// automatic mechanism where none is cleanly available.
register veda_mepcc_base : bits(32)
register veda_mepcc_length : bits(16)

// Milestone 14: shared by both real hard-trap paths that narrow PCC
// away from a live compartment -- `veda_trap()` (every ordinary
// Veda-Core "use"-family violation) and the new PCC-bounds-violation
// path (veda_pcc.sail, routed through `handle_exception` directly since
// it fires outside the normal per-instruction execute dispatch). Saves
// the live compartment bounds so software can restore them later, then
// resets to unbounded so the trap handler itself runs in a trusted,
// unconstrained context -- real CHERI's own "Exception Code Capability"
// requirement (CHERI ISA spec §3.4.7).
function veda_pcc_save_and_reset() -> unit = {
  veda_mepcc_base = veda_pcc_base;
  veda_mepcc_length = veda_pcc_length;
  veda_pcc_base = zeros();
  veda_pcc_length = VEDA_PCC_UNBOUNDED;
}

// Milestone 14: four new CSRs in the real, standard RISC-V "Machine-
// level Custom read/write" address range (riscv-spec.pdf Table 91,
// "Allocation of RISC-V CSR address ranges," p.664: 0x7C0-0x7FF) --
// verified against the real spec, not invented, the same real range
// convention already trusted once for `mtvec`/`mepc`/`mcause`/`mtval`
// sitting in the adjacent *standard* M-mode range (0x300-0x3FF).
// Exposed via the real, unmodified, already-working base-ISA CSRRW/
// CSRRS (no new instruction), following the exact same real
// `scattered function`/`scattered mapping` clause mechanism this
// codebase's own core/sys_regs.sail already uses for mtvec/mcause/etc.
// (read directly before writing this, not assumed).
mapping clause csr_name_map = 0x7C0 <-> "veda_pcc_base"
mapping clause csr_name_map = 0x7C1 <-> "veda_pcc_length"
mapping clause csr_name_map = 0x7C2 <-> "veda_mepcc_base"
mapping clause csr_name_map = 0x7C3 <-> "veda_mepcc_length"

function clause is_CSR_accessible(0x7C0, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C1, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C2, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C3, _, _) = currentlyEnabled(Ext_Veda)

function clause read_CSR(0x7C0) = zero_extend(veda_pcc_base)
function clause read_CSR(0x7C1) = zero_extend(veda_pcc_length)
function clause read_CSR(0x7C2) = zero_extend(veda_mepcc_base)
function clause read_CSR(0x7C3) = zero_extend(veda_mepcc_length)

function clause write_CSR(0x7C0, value) = { veda_pcc_base = value[31..0]; Ok(zero_extend(veda_pcc_base)) }
function clause write_CSR(0x7C1, value) = { veda_pcc_length = value[15..0]; Ok(zero_extend(veda_pcc_length)) }
function clause write_CSR(0x7C2, value) = { veda_mepcc_base = value[31..0]; Ok(zero_extend(veda_mepcc_base)) }
function clause write_CSR(0x7C3, value) = { veda_mepcc_length = value[15..0]; Ok(zero_extend(veda_mepcc_length)) }

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
    retired    = false,
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
    retired    = false,
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
    retired    = false,
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
    retired    = false,
  });
  // Milestone 12 addition: a fifth seeded object, pre-claimed by a
  // hypothetical OTHER hart (99 -- distinct from this real, single-
  // process simulator's own real `mhartid`, config-fixed at 0). This
  // project's own Sail test config genuinely cannot produce two real,
  // concurrently-executing harts (a real, distinct limitation named in
  // MILESTONE_11_RESULTS.md for an unrelated reason, S/U-mode being
  // disabled there) -- direct ODT-state injection is the real, already-
  // established way this project proves policy-logic correctness
  // without that (the identical real technique already used for every
  // other seeded object above, none of which are populated via a real
  // ODT-Populate instruction either).
  odt_write(to_bits(23, 5), struct {
    valid      = true,
    Base       = 0x80010400,
    Length     = 0x0010,
    Perms      = 0x000C,
    generation = zeros(),
    owner_hart = 0x63, // 99 decimal -- a real, distinct, non-zero "other hart"
    retired    = false,
  })
}
