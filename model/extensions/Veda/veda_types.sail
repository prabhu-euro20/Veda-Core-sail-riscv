// Veda-Core formal model: capability and ODT-entry types.
//
// Milestone V-A (FORMAL_VERIFICATION_PLAN.md): capability struct, CRF index
// type, ODT entry type, extension registration. Field layout matches
// VEDA_CORE_SPEC.md Section 2 exactly, including the Base/Length/Offset
// fix made in this same session (Length replaces the original inconsistent
// 32-bit Limit field; Offset is a new field neither the original field
// table nor this model had before).
//
// Scattered extension registration -- deliberately kept in this new file
// rather than editing core/extensions.sail, since Sail's scattered
// enum/function mechanism supports this and it keeps the base checkout's
// own files untouched.
enum clause extension = Ext_Veda
mapping clause extensionName = Ext_Veda <-> "veda"
function clause hartSupports(Ext_Veda) = config extensions.Veda.supported
function clause currentlyEnabled(Ext_Veda) = hartSupports(Ext_Veda)

// Capability Register File index. 16 registers (c0-c15, VEDA_CORE_SPEC.md
// Section 2) need 4 bits. Named vcapidx/vcapno (not cregidx/cregno) to
// avoid a real name collision with core/regs.sail's existing cregidx,
// which is RVC's unrelated 3-bit compressed-register index -- found by
// reading core/regs.sail directly before writing this file, not assumed.
newtype vcapidx = Vcapidx : bits(4)
newtype vcapno = Vcapno : range(0, 15)

function vcapidx_to_vcapno(Vcapidx(b) : vcapidx) -> vcapno = Vcapno(unsigned(b))
function vcapno_to_vcapidx(Vcapno(b) : vcapno) -> vcapidx = Vcapidx(to_bits(4, b))

mapping encdec_vcap : vcapidx <-> bits(4) = { Vcapidx(r) <-> r }

// Real, working precedent for a bidirectional register-name mapping is
// core/regs.sail's own `reg_abi_name_raw`/`reg_arch_name_raw` explicit
// bit-pattern <-> string enumeration tables (confirmed real via a
// separate compile error: `mapping clause assembly` must be built
// entirely from bidirectional `mapping`s to stay parseable, and the
// plain one-way function `dec_str` does not satisfy that -- so this is a
// literal table, not a decimal-formatting shortcut).
mapping vcap_name : bits(4) <-> string = {
  0x0 <-> "c0",  0x1 <-> "c1",  0x2 <-> "c2",  0x3 <-> "c3",
  0x4 <-> "c4",  0x5 <-> "c5",  0x6 <-> "c6",  0x7 <-> "c7",
  0x8 <-> "c8",  0x9 <-> "c9",  0xa <-> "c10", 0xb <-> "c11",
  0xc <-> "c12", 0xd <-> "c13", 0xe <-> "c14", 0xf <-> "c15",
}

// The capability register's field layout, VEDA_CORE_SPEC.md Section 2:
//   Tag(1, out-of-band) + Object_ID(23) + Base(32) + Length(16) + Offset(16)
//   + Perms(16) + otype(16) + Reserved(8) = 127, +1 padding = 128 bits.
// Object_ID widened from 16 to 23 bits, and Reserved narrowed from 15 to 8
// (now fully consumed by the generation counter, no spare bits), in the
// post-Milestone-V-A scaling-barrier research pass -- see
// veda-core/SCALING_BARRIERS_RESEARCH.md Section 3 for the bit-budget
// arithmetic and veda-core/VEDA_CORE_SPEC.md Section 2 for the spec change
// this mirrors exactly.
// Tag is modeled separately (crTags, veda_regs.sail) since it is
// out-of-band and not part of the 128-bit value, matching how mem_meta
// (core/mem_metadata.sail) keeps the memory-resident tag out-of-band from
// data too.
struct capability = {
  Object_ID : bits(23),
  Base      : bits(32),
  Length    : bits(16),
  Offset    : bits(16),
  Perms     : bits(16),
  otype     : bits(16),
  Reserved  : bits(8),
}

// otype sentinel, VEDA_CORE_SPEC.md Section 2: all-ones = UNSEALED.
let UNSEALED_OTYPE : bits(16) = 0xFFFF

let zero_capability : capability = struct {
  Object_ID = zeros(),
  Base      = zeros(),
  Length    = zeros(),
  Offset    = zeros(),
  Perms     = zeros(),
  otype     = UNSEALED_OTYPE,
  Reserved  = zeros(),
}

function isSealedCap(c : capability) -> bool = c.otype != UNSEALED_OTYPE

// Pack/unpack a capability to/from its real 128-bit memory representation
// -- Milestone 7 (OCL.C/OCS.C, VEDA_CORE_SPEC.md's own field order and bit
// budget, Section 2: "Object_ID(23)+Base(32)+Length(16)+Offset(16)+
// Perms(16)+otype(16)+Reserved(8) = 127, +1 padding bit = 128"). Packed
// MSB-to-LSB in the same order the spec's own field table lists them, with
// the single pad bit as the true LSB (bit 0) -- an arbitrary but fixed,
// self-consistent choice, since the spec names a padding bit but never
// assigns it a position. Tag is deliberately NOT part of this 128-bit
// value (Section 2: "out-of-band... not counted in the 128") -- it is
// packed/unpacked separately, via mem_meta (core/mem_metadata.sail),
// exactly mirroring how it is already kept separate from the capability
// register's own 128 data bits (crTags, veda_regs.sail).
function veda_cap_pack(c : capability) -> bits(128) =
  c.Object_ID @ c.Base @ c.Length @ c.Offset @ c.Perms @ c.otype @ c.Reserved @ 0b0

function veda_cap_unpack(v : bits(128)) -> capability = struct {
  Object_ID = v[127..105],
  Base      = v[104..73],
  Length    = v[72..57],
  Offset    = v[56..41],
  Perms     = v[40..25],
  otype     = v[24..9],
  Reserved  = v[8..1],
}

// Perms bit-position assignment -- a genuinely new decision made while
// writing this model, not previously fixed anywhere: VEDA_CORE_SPEC.md
// Section 2 names 13 permission bits but never assigned each one a bit
// index. CHERI's own real permission-bit ordering was not verified this
// session (would need a fresh, dedicated read of that part of the CHERI
// spec), so this is a fresh, systematic assignment, not a copied one --
// stated plainly so it isn't presented as more sourced than it is.
// Typed as `range(0,15)`, not plain `int` -- a real compile error (found
// via an actual build attempt, not assumed) showed that indexing a
// bitvector with a plain, unconstrained `int` fails Sail's static
// in-bounds proof obligation. The real, working precedent for indexing
// with a resolved constant is `misa[C] == 0b1` (core/misa_ext.sail,
// already compiling in this codebase) -- `range(0,15)` gives the same
// static provability plain `int` doesn't.
let PERM_GLOBAL                        : range(0,15) = 0
let PERM_EXECUTE                       : range(0,15) = 1
let PERM_LOAD                          : range(0,15) = 2
let PERM_STORE                         : range(0,15) = 3
let PERM_LOAD_CAPABILITY               : range(0,15) = 4
let PERM_STORE_CAPABILITY              : range(0,15) = 5
let PERM_STORE_LOCAL_CAPABILITY        : range(0,15) = 6
let PERM_ACCESS_SYSTEM_REGISTERS       : range(0,15) = 7
let PERM_SEAL                          : range(0,15) = 8
let PERM_UNSEAL                        : range(0,15) = 9
let PERM_INVOKE                        : range(0,15) = 10
let PERM_SET_CID                       : range(0,15) = 11
let PERM_NMC_COMPUTE                   : range(0,15) = 12
// bits 13-15 spare

function permBit(perms : bits(16), b : range(0,15)) -> bool = perms[b] == 0b1

// The Object Descriptor Table entry, VEDA_CORE_SPEC.md Section 5.1: flat,
// single-level, system-wide, indexed directly by the 23-bit Object_ID
// (widened from 16 bits this pass, see the `capability` struct comment
// above). Generation narrowed from 15 to 8 bits this same pass -- no
// longer "the simplest choice," now a deliberate match to CHERI-D's real,
// empirically-derived per-allocation generation-counter width (arXiv
// 2606.19055; veda-core/SCALING_BARRIERS_RESEARCH.md Section 3/6). No
// spare bits remain in Reserved after this change.
// Milestone 12: `owner_hart` (VEDA_CORE_SPEC.md §4.1, real, previously-
// named gap: "an owner-hart field in the ODT entry, checked at Bind/
// Rebind time... real, identified future work"). 8 bits -- a real,
// stated, bounded design choice mirroring this project's own established
// "real, bounded, honestly-scoped" discipline (the same reasoning
// already applied to the ODT generation counter's own 8-bit width,
// SCALING_BARRIERS_RESEARCH.md §3/6 -- 256 harts is a real, generous
// ceiling for this design's own target scale, not a claim of matching
// mhartid's own full XLEN width). VEDA_OWNER_UNOWNED is the sentinel: an
// object with no live bind yet (freshly populated, or destroyed and
// repopulated) belongs to no hart until the first real Bind claims it.
let VEDA_OWNER_UNOWNED : bits(8) = 0xFF

struct odt_entry = {
  valid      : bool,
  Base       : bits(32),
  Length     : bits(16),
  Perms      : bits(16),
  generation : bits(8),
  owner_hart : bits(8),
}

let empty_odt_entry : odt_entry = struct {
  valid      = false,
  Base       = zeros(),
  Length     = zeros(),
  Perms      = zeros(),
  generation = zeros(),
  owner_hart = VEDA_OWNER_UNOWNED,
}

// Milestone V-B: Veda-Atomic's op-select enum (VEDA_CORE_SPEC.md Section 1)
// -- moved here, not left in veda_atomic_insts.sail, for the identical
// real reason vcapidx lives in this `before sys`-ordered module and not
// in veda_bind_insts.sail: a real compile error ("Undefined type
// veda_atomicop... this could also be caused by using a type defined
// after the 'scattered union' declaration") confirmed a scattered `union
// clause instruction` needs any type it references to already be visible
// from an earlier-ordered module, not just earlier in the same file.
enum veda_atomicop = {VEDA_AMOSWAP, VEDA_AMOADD, VEDA_AMOXOR, VEDA_AMOAND, VEDA_AMOOR, VEDA_AMOMIN, VEDA_AMOMAX, VEDA_AMOMINU, VEDA_AMOMAXU}

// Milestone V-B: Veda-Cap query family's selector enum, same reason.
enum veda_capquery = {VEDA_CGETBASE, VEDA_CGETLEN, VEDA_CGETPERM, VEDA_CGETTAG, VEDA_CGETTYPE, VEDA_CGETADDR, VEDA_CGETOFFSET}
