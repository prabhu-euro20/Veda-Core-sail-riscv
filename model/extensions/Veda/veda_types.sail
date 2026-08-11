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

// The capability register's field layout -- Phase 1 increment 2, the
// 256-bit respec (veda-core-linux design/DESIGN_01_CAPABILITY_FORMAT_RESPEC.md,
// "Resolved implementation decisions"):
//   Tag(1, out-of-band) + Object_ID(44) + Base(56) + Length(40) + Offset(40)
//   + Perms(16) + otype(16) + generation(24) + flags(20) = 256 exactly.
// There is NO padding bit any more: the old 128-bit layout was 127 data bits
// + 1 pad; 256 is exact, so the pad (and the unpack's bit-0 skip) is gone.
//
// Why each width (DESIGN_01 "Problem: four spec-level walls"): the previous
// format could not *express* Linux-scale objects at all -- Length(16) capped
// an object at 64 KiB, Base(32) capped physical memory at 4 GiB,
// Object_ID(23) capped live objects at 8.4M, and the generation counter
// (carried in the old `Reserved`) retired a slot after 255 destroy/reuse
// cycles. Widening the SEPARATE CRF is what makes this cheap: the 64-bit GPR
// datapath is untouched (CRF_ARCHITECTURE_ALIGNMENT_VERDICT's own
// keep-it-separate verdict is the enabler, not an obstacle).
//
// `Reserved` is renamed to `generation` because that is what it always
// literally was (see the old comment: "now fully consumed by the generation
// counter"). Sail's type checker turns every stale `.Reserved` into a compile
// error rather than a silent bug, which is exactly why the rename is safe.
// `flags` is new and deliberately OPAQUE: 20 reserved bits, minted as zeros
// by Bind, no instruction reads or writes individual bits yet. DESIGN_01
// names COW-hint/residency-mirror/CID as eventual tenants, but assigning
// positions (especially a CID width) before the DESIGN_00 namespace work
// would be an under-sourced guess.
//
// Tag is modeled separately (crTags, veda_regs.sail) since it is
// out-of-band and not part of the 256-bit value, matching how mem_meta
// (core/mem_metadata.sail) keeps the memory-resident tag out-of-band from
// data too.
struct capability = {
  Object_ID  : bits(44),
  Base       : bits(56),
  Length     : bits(40),
  Offset     : bits(40),
  Perms      : bits(16),
  otype      : bits(16),
  generation : bits(24),
  flags      : bits(20),
}

// otype sentinel, VEDA_CORE_SPEC.md Section 2: all-ones = UNSEALED.
let UNSEALED_OTYPE : bits(16) = 0xFFFF

// Minimal OS kernel Milestone B (MINIMAL_OS_KERNEL_DESIGN.md): the reserved
// "sentry" otype, term-for-term the proportional analog of real CHERI's own
// `2^XLEN-2` (CHERI ISA spec Table 3.2, p.79, immediately below its own
// `2^XLEN-1` = unsealed entry) -- a capability sealed with this otype is a
// hardware-minted sentry (VEDA_CSEALENTRY), verifiable by VEDA_OCRETURN with
// a single capability operand instead of CSeal/CUnseal's general two-operand
// type-authority check. Trustworthy only because VEDA_CSEAL's own
// authorization (veda_cap_insts.sail) is hardened to refuse this value as a
// requested otype, exactly mirroring real CSeal's own `cursor <=
// cap_max_otype` bound -- ordinary software-directed sealing can never
// produce it, only VEDA_CSEALENTRY's own fixed-constant assignment can.
let VEDA_OTYPE_SENTRY : bits(16) = 0xFFFE

let zero_capability : capability = struct {
  Object_ID  = zeros(),
  Base       = zeros(),
  Length     = zeros(),
  Offset     = zeros(),
  Perms      = zeros(),
  otype      = UNSEALED_OTYPE,
  generation = zeros(),
  flags      = zeros(),
}

function isSealedCap(c : capability) -> bool = c.otype != UNSEALED_OTYPE

// Phase 1 increment 2 (DESIGN_01 decision 7): Ext_Veda is now an RV64-only
// extension. Base(56), Object_ID(44), Length(40) and Offset(40) all exceed
// 32 bits, so `zero_extend(field) : xlenbits` is ill-typed whenever xlen
// could be 32 -- and this codebase already learned, the hard way, that an
// encdec `when ... & xlen == 64` guard is NOT visible to the type checker
// inside an execute body (see the recorded lesson at VEDA_NMC_ADD_D).
//
// So capability address arithmetic is done in an explicit 64-bit domain and
// narrowed once, here, at the boundary. `truncate` is well-typed for both
// xlen values because core/xlen.sail constrains xlen to {32, 64}, hence
// xlen <= 64. On RV64 this is an exact identity; on RV32 every Veda
// instruction fails to decode at all, so the narrowing is unreachable --
// the extension is gated off, not silently truncating real values.
function veda_to_xlen(v : bits(64)) -> xlenbits = truncate(v, xlen)

// Pack/unpack a capability to/from its real 256-bit memory representation
// (OCL.C/OCS.C). Packed MSB-to-LSB in the same order the field table lists
// them. Unlike the old 128-bit layout there is NO pad bit: the eight fields
// sum to exactly 256 (44+56+40+40+16+16+24+20), so pack/unpack were
// re-derived field-by-field rather than width-patched -- the old
// "@ 0b0" pad term and the unpack's bit-0 skip are gone.
//
// Bit ranges, stated explicitly because a silent off-by-one here would be a
// capability-corruption bug the type checker cannot catch (every slice is
// well-typed, only the *boundaries* carry meaning):
//   Object_ID  [255..212]  44
//   Base       [211..156]  56
//   Length     [155..116]  40
//   Offset     [115..76]   40
//   Perms      [75..60]    16
//   otype      [59..44]    16
//   generation [43..20]    24
//   flags      [19..0]     20
//
// Tag is deliberately NOT part of this 256-bit value -- it is carried
// out-of-band via mem_meta (core/mem_metadata.sail), exactly mirroring how
// it is already kept separate from the capability register's own data bits
// (crTags, veda_regs.sail). NOTE (DESIGN_01 decision 1): because a
// capability is now 32 bytes, the memory tag granule widens to 32 bytes so
// one capability still occupies exactly ONE granule. Keeping a 16-byte
// granule would let a plain store rewrite bytes 16..31 -- which hold Perms,
// otype and generation -- while the start granule's tag survived, i.e. a
// direct permission/generation forgery primitive.
function veda_cap_pack(c : capability) -> bits(256) =
  c.Object_ID @ c.Base @ c.Length @ c.Offset @ c.Perms @ c.otype @ c.generation @ c.flags

function veda_cap_unpack(v : bits(256)) -> capability = struct {
  Object_ID  = v[255..212],
  Base       = v[211..156],
  Length     = v[155..116],
  Offset     = v[115..76],
  Perms      = v[75..60],
  otype      = v[59..44],
  generation = v[43..20],
  flags      = v[19..0],
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
// single-level, system-wide.
//
// PHASE 1 INCREMENT 2 SCOPE NOTE (DESIGN_01 decision 6, stated so the
// asymmetry is not mistaken for an oversight): the CAPABILITY widened to
// Object_ID(44)/Base(56)/Length(40)/generation(24), but this ODT ENTRY
// deliberately did NOT. Bind zero-extends the still-narrow entry fields into
// the wide capability, which is a lossless bridge (a 32-bit Base is a valid
// 56-bit Base). Keeping the entry narrow here keeps the atomic struct change
// smaller and defers the genuinely separate ODT-Populate operand redesign --
// Base56+Length40+Perms16 = 112 bits no longer fits the single-GPR packed
// descriptor, and veda_attr (bits(32)) cannot hold Length40+Perms16 -- to its
// own tested increment. Until then the ODT's own domains (Base 32-bit,
// Length 16-bit, generation 8-bit) remain the real, honest limit on what an
// object can be, regardless of what the capability format can express.
//
// The table is indexed by the low bits of the Object_ID with an explicit
// out-of-range guard (veda_regs.sail): the capability legitimately carries a
// full 44-bit Object_ID, but a flat vector(2^44) is ~300 TiB and will not
// build, so ids at or above the modeled table size read as OBJECT_NOT_FOUND.
// That bound is the honest interim until the segmented-Object_ID trilemma
// (DESIGN_06) is designed -- the same "real, bounded, honestly-scoped"
// discipline as the RTL's own 256-entry ODT.
//
// Generation narrowed from 15 to 8 bits in an earlier pass -- no
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
  // Mirrors RTL Milestone 16 (rtl/MILESTONE_16_RESULTS.md,
  // veda-core/ARCHITECTURE_IMPROVEMENT_FINDINGS.md Finding 2): the
  // 8-bit `generation` counter's own real ABA-problem wraparound,
  // empirically reproduced (256 real Destroy operations on the same
  // slot wrap it exactly back to a stale capability's own cached
  // value). Simply saturating `generation` at 0xff is not sufficient by
  // itself -- every future re-populate would then also land on 0xff,
  // making every incarnation from that point on permanently
  // indistinguishable rather than only periodically. `retired` closes
  // this: once `generation` would wrap, the slot is permanently
  // retired instead -- ODT-Populate against it becomes Illegal
  // -Instruction() from then on. This is a deliberate divergence from
  // CHERI-D's own real, published precedent (Wang et al., arXiv
  // 2606.19055; SCALING_BARRIERS_RESEARCH.md Section 3/6), which
  // accepts wraparound as a statistically-rare residual risk empirically
  // derived from real allocator traces -- justified here specifically
  // because Veda-Core's own stated priority is security over
  // throughput/compatibility, and because this project now has a real,
  // empirically demonstrated exploit on its own RTL, not merely a
  // theoretical risk.
  retired    : bool,
}

let empty_odt_entry : odt_entry = struct {
  valid      = false,
  Base       = zeros(),
  Length     = zeros(),
  Perms      = zeros(),
  generation = zeros(),
  owner_hart = VEDA_OWNER_UNOWNED,
  retired    = false,
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

// Minimal OS kernel Milestone A (MINIMAL_OS_KERNEL_DESIGN.md): OSpecialRW's
// own SCR-selector enum, same real scattered-ordering reason as above --
// placed here preemptively rather than re-discovering the identical
// compile error a third time. OSpecialRW's own previously-hardcoded
// `00000` field (veda_cap_insts.sail) becomes this real selector: 0 = ODA
// (Milestone 11's own existing register, unchanged, so every pre-existing
// `ospecialrw` encoding -- which always had that field as literal zero --
// continues to mean exactly what it always meant, a real, verified
// backward-compatibility property, not just an assumption), 1 = TSC (the
// new Trusted Stack Capability this milestone adds).
//
// SSC (Stack-Spill Capability): a third selector, added to let ordinary
// compiled C's ABI-mandated callee-saved-register spills/reloads route
// through real OCL.D/OCS.D checks instead of raw sd/ld (which
// Milestone 19's purecap rule unconditionally traps inside a live
// compartment). Deliberately NOT persistent-and-OCInvoke-transparent like
// ODA/TSC above -- verified directly against VEDA_OCINVOKE's own execute
// clause that it touches only veda_pcc_base/_length and IDC today, so an
// SSC following the same "untouched by OCInvoke" pattern would let a
// callee compartment silently inherit full read/write access to the
// caller's entire stack region, a real leak bigger than the purecap trap
// this exists to safely replace. VEDA_OCINVOKE itself is extended (see
// its own execute clause) to save/swap SSC on every invoke instead.
enum veda_scr = {VEDA_SCR_ODA, VEDA_SCR_TSC, VEDA_SCR_SSC}
