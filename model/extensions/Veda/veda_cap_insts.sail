// Veda-Core formal model: Veda-Cap (Custom-2, VEDA_CORE_SPEC.md Section 1),
// Milestone V-B. Starts with OCA (Object Capability Adjust); the query
// family and CSetBounds/CSeal/CUnseal are added later in this same file.
//
// R-type, Custom-2 opcode (0b1011011):
//   31                    25  24      20   19      15   14    12   11      7   6        0
//   [   funct7 (op-select)  ][   rs2    ][   rs1    ][funct3(dest-kind)][   rd    ][1011011]
//
// rs1/rd are Capability Registers when funct3's dest-kind bit says so,
// packed into their 5-bit R-type slots the identical way OCL/OCS already
// do (a fixed 0 bit above the real 4-bit vcapidx, VEDA_CORE_SPEC.md
// Section 3's own "future-proofs against growing past 16 capability
// registers" reasoning, already established, not reinvented here).

// OCA: funct7 = 0001010. funct3 = destination-register-file selector
// (Section 1: "0 = GPR..., 1 = Capability Register"); OCA's result is
// always a capability, so funct3 = 0b001 (only the low bit carries
// meaning, matching this ISA's own established habit of using a field
// as a small literal enum -- e.g. Object-Bind's imm[1:0] mode field).
union clause instruction = VEDA_OCA : (regidx, vcapidx, vcapidx)

mapping clause encdec = VEDA_OCA(rs2, rs1, rd)
  <-> 0b0001010 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

// Semantics, VEDA_CORE_SPEC.md Section 1: "rd = rs1 with its Offset field
// replaced by rs1.Offset + rs2 (a GPR-held signed delta). If the resulting
// value would fall outside [0, rs1.Length), or if rs1 was already sealed,
// rd.Tag is cleared rather than trapping -- a soft-fail." Directly
// mirrors CHERI's real CIncOffset text (quoted in the spec): cd is
// *unconditionally* set to the modified fields, and only the tag is
// conditionally cleared -- not "leave rd unchanged on failure". One
// reasoned addition beyond what the spec text says explicitly, flagged as
// such rather than silently invented: an already-untagged rs1 can't
// produce a tagged rd either (CTag(capidx) is included in the tag
// computation) -- a source capability that was never valid can't become
// valid just by adjusting its offset, matching how a derived value can
// never be "more valid" than what it was derived from in every other
// capability system this project's research has read in full.
function clause execute VEDA_OCA(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let cap = C(capidx);
  let delta : xlenbits = X(rs2);
  // Bitvector-native wraparound add (matching the real, local AMO
  // implementation's own approach, extensions/A/zaamo_insts.sail --
  // `rs2_val + loaded`, no detour through `int`) rather than a signed
  // `int` add followed by `to_bits`: a real compile error ("Could not
  // resolve quantifiers for to_bits... 0 <= new_offset_wide & ... < 2^16")
  // showed Sail can't statically prove an unconstrained `int` fits in 16
  // bits, the identical class of issue already documented and fixed once
  // in Milestone V-A (bitvector indexing needs a statically-provable
  // bound). Fixed by adding in fixed-width bits (two's-complement
  // wraparound correctly represents a "negative" result as a large
  // unsigned pattern) and slicing the low 16 bits directly -- both are
  // statically valid on a known-width vector, no bounds proof needed.
  // `xlenbits`, not hardcoded `bits(64)` -- OCA has no `xlen == 64` gate
  // (unlike OCL.D/OCS.D/NMC_ADD.D), so a real type error ("Failed to
  // prove constraint: xlen == 64") confirmed the width must stay generic.
  // Offset is 40 bits now, so this must widen through the explicit
  // 64-bit domain (Ext_Veda is RV64-only, DESIGN_01 decision 7).
  let offset_ext : bits(64) = zero_extend(cap.Offset);
  let sum : bits(64) = offset_ext + zero_extend(delta);
  let sum_signed : int = signed(sum);
  let out_of_range : bool = sum_signed < 0 | sum_signed >= unsigned(cap.Length);
  let new_cap : capability = struct {
    Object_ID = cap.Object_ID,
    Base      = cap.Base,
    Length    = cap.Length,
    Offset    = sum[39..0],
    Perms     = cap.Perms,
    otype     = cap.otype,
    generation = cap.generation,
    flags      = cap.flags,
  };
  let rdno = vcapidx_to_vcapno(rd);
  wC(rdno, new_cap);
  wCTag(rdno, CTag(capidx) & not(out_of_range) & not(isSealedCap(cap)));
  RETIRE_SUCCESS
}

mapping clause assembly = VEDA_OCA(rs2, rs1, rd)
  <-> "oca" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)

// Veda-Cap query family, VEDA_CORE_SPEC.md Section 1: "CGetBase, CGetLen,
// CGetPerm, CGetTag, CGetType, CGetAddr, CGetOffset (metadata queries, one
// funct7 value each)", funct7 = 0000000-0000110 in that exact listed
// order. funct3 = 0b000 (dest-kind = GPR, Section 1's "0 = result goes to
// a GPR"); rs2 is unused for queries (spec: "unused for queries").
//
// No Tag/Seal/bounds checks at all -- deliberately, not an oversight:
// Section 1's own "Sealed-capability enforcement" text states the query
// family "remains unconditionally allowed on sealed capabilities,
// unchanged", matching CHERI's own real principle that capability
// *metadata* is always inspectable even when the capability itself is
// sealed or untagged (CGetTag's entire purpose is to report an untagged
// capability's tag as false, which it couldn't do if reading the tag
// itself were gated by the tag being true).
// veda_capquery itself lives in veda_types.sail, not here -- the same
// scattered-union ordering reason veda_atomicop does (see the comment
// there), applied preemptively this time rather than re-discovering it
// via a second identical compile error.
mapping encdec_veda_capquery : veda_capquery <-> bits(7) = {
  VEDA_CGETBASE   <-> 0b0000000,
  VEDA_CGETLEN    <-> 0b0000001,
  VEDA_CGETPERM   <-> 0b0000010,
  VEDA_CGETTAG    <-> 0b0000011,
  VEDA_CGETTYPE   <-> 0b0000100,
  VEDA_CGETADDR   <-> 0b0000101,
  VEDA_CGETOFFSET <-> 0b0000110,
}

union clause instruction = VEDA_CAPQUERY : (veda_capquery, vcapidx, regidx)

mapping clause encdec = VEDA_CAPQUERY(q, rs1, rd)
  <-> encdec_veda_capquery(q) @ 0b00000 @ 0b0 @ encdec_vcap(rs1) @ 0b000 @ encdec_reg(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

function clause execute VEDA_CAPQUERY(q, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let cap = C(capidx);
  // CGetAddr = Base + Offset (the real, resolved location), CGetOffset =
  // Offset alone, CGetLen = Length -- the three-way split Section 1/2's
  // field-fix text already established, not a new decision here.
  let result : xlenbits = match q {
    VEDA_CGETBASE   => veda_to_xlen(zero_extend(cap.Base)),
    VEDA_CGETLEN    => veda_to_xlen(zero_extend(cap.Length)),
    VEDA_CGETPERM   => zero_extend(cap.Perms),
    VEDA_CGETTAG    => zero_extend(bool_bit(CTag(capidx))),
    VEDA_CGETTYPE   => zero_extend(cap.otype),
    VEDA_CGETADDR   => veda_to_xlen(zero_extend(cap.Base) + zero_extend(cap.Offset)),
    VEDA_CGETOFFSET => veda_to_xlen(zero_extend(cap.Offset)),
  };
  X(rd) = result;
  RETIRE_SUCCESS
}

mapping veda_capquery_mnemonic : veda_capquery <-> string = {
  VEDA_CGETBASE   <-> "cgetbase",
  VEDA_CGETLEN    <-> "cgetlen",
  VEDA_CGETPERM   <-> "cgetperm",
  VEDA_CGETTAG    <-> "cgettag",
  VEDA_CGETTYPE   <-> "cgettype",
  VEDA_CGETADDR   <-> "cgetaddr",
  VEDA_CGETOFFSET <-> "cgetoffset",
}

mapping clause assembly = VEDA_CAPQUERY(q, rs1, rd)
  <-> veda_capquery_mnemonic(q) ^ spc() ^ reg_name(rd) ^ sep() ^ vcap_name(encdec_vcap(rs1))

// CSetBounds / CSetBoundsExact, VEDA_CORE_SPEC.md Section 1, funct7 =
// 0001000 / 0001001. Not in this pass's original task list, added here
// because the spec's own "Sealed-capability enforcement" text explicitly
// names both as part of the manipulate/soft-fail family this pass is
// implementing, and Custom-2's funct7 table already reserves both slots
// with a fully-specified semantics -- leaving them unbuilt would leave
// Custom-2 visibly incomplete for a small, well-understood marginal cost.
//
// A real, honest observation, not glossed over: the spec text says
// "CSetBoundsExact traps instead of rounding if the requested bounds
// aren't exactly representable; CSetBounds rounds" -- mirroring CHERI's
// own real distinction, which exists because CHERI's bounds are a
// floating-point-style *compressed* encoding that can genuinely lose
// precision. Veda-Core's `Length` field (Section 2) is a plain,
// uncompressed 16-bit value with no such compression -- every value in
// [0, 65535] is exactly representable, so "not exactly representable"
// cannot occur here at all. The two instructions are therefore
// behaviorally identical in this implementation (both soft-fail
// identically on the one real failure mode this field design has --
// exceeding cs1's own current window, or cs1 being sealed) -- not an
// oversight, a direct, honest consequence of a field-width decision made
// earlier in this project, stated plainly rather than inventing an
// artificial difference the current design doesn't actually have.
union clause instruction = VEDA_CSETBOUNDS      : (regidx, vcapidx, vcapidx)
union clause instruction = VEDA_CSETBOUNDSEXACT : (regidx, vcapidx, vcapidx)

mapping clause encdec = VEDA_CSETBOUNDS(rs2, rs1, rd)
  <-> 0b0001000 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

mapping clause encdec = VEDA_CSETBOUNDSEXACT(rs2, rs1, rd)
  <-> 0b0001001 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

// Shared body for both: "cd.Base = cs1.Base + cs1.Offset... cd.Length =
// rs2... cd.Offset = 0... clear cd.Tag if cs1 was already sealed or if
// the requested bounds would exceed cs1's own current window" (Section 1).
function veda_setbounds(rs2 : regidx, rs1 : vcapidx, rd : vcapidx) -> unit = {
  let capidx = vcapidx_to_vcapno(rs1);
  let cap = C(capidx);
  // Length is 40 bits now, so the requested value is taken through the
  // explicit 64-bit domain before slicing (a direct xlenbits[39..0] is
  // not provably in range when xlen might be 32).
  let new_length : bits(64) = zero_extend(X(rs2));
  // "exceed cs1's own current window": the narrowed window (starting at
  // the current position, cs1.Offset) must not extend past cs1's own
  // Length -- monotonic narrowing, never widening, the same principle
  // this project's cross-cutting design note (Section, closing) already
  // states explicitly for every capability-deriving instruction.
  let window_ok : bool = unsigned(cap.Offset) + unsigned(new_length) <= unsigned(cap.Length);
  let ok : bool = CTag(capidx) & not(isSealedCap(cap)) & window_ok;
  let new_cap : capability = struct {
    Object_ID = cap.Object_ID,
    Base      = cap.Base + zero_extend(cap.Offset),
    Length    = new_length[39..0],
    Offset    = zeros(),
    Perms     = cap.Perms,
    otype     = cap.otype,
    generation = cap.generation,
    flags      = cap.flags,
  };
  let rdno = vcapidx_to_vcapno(rd);
  wC(rdno, new_cap);
  wCTag(rdno, ok)
}

function clause execute VEDA_CSETBOUNDS(rs2, rs1, rd) = {
  veda_setbounds(rs2, rs1, rd);
  RETIRE_SUCCESS
}

function clause execute VEDA_CSETBOUNDSEXACT(rs2, rs1, rd) = {
  veda_setbounds(rs2, rs1, rd);
  RETIRE_SUCCESS
}

mapping clause assembly = VEDA_CSETBOUNDS(rs2, rs1, rd)
  <-> "csetbounds" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)

mapping clause assembly = VEDA_CSETBOUNDSEXACT(rs2, rs1, rd)
  <-> "csetboundsexact" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)

// CSeal / CUnseal, VEDA_CORE_SPEC.md Section 1, funct7 = 0010000 /
// 0010001. Unlike every other Custom-2 instruction so far, `rs2` here is
// a *second Capability Register* (the type-authority capability), not a
// GPR -- the spec's own text confirms this is a direct, unmodified match
// to CHERI-RISC-V's real CSeal/CUnseal encoding shape.
//
// Real CHERI semantics (quoted in the spec, verified against the actual
// CHERI ISA spec pp.226/241-242): cd is *unconditionally* set to cs1 with
// otype replaced, tag cleared only if authorization fails or cs1 was
// already (un)sealed appropriately -- the identical "always write the
// fields, conditionally clear the tag" pattern already used for OCA
// above, not a new idiom introduced here.
//
// Veda-Core's term-for-term adaptation (Section 1): CHERI's "address" ->
// Offset; CHERI's "cursor within cs2's base/top" -> "cs2.Offset within
// cs2's own [0, Length)"; CHERI's "cursor <= max_otype" -> cs2.Offset !=
// UNSEALED_OTYPE (0xFFFF), since using 0xFFFF as a "sealed" otype would
// silently alias the UNSEALED sentinel, a real, meaningful check, not a
// mechanical copy of CHERI's own max_otype bound.
union clause instruction = VEDA_CSEAL   : (vcapidx, vcapidx, vcapidx)
union clause instruction = VEDA_CUNSEAL : (vcapidx, vcapidx, vcapidx)

mapping clause encdec = VEDA_CSEAL(rs2, rs1, rd)
  <-> 0b0010000 @ 0b0 @ encdec_vcap(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

mapping clause encdec = VEDA_CUNSEAL(rs2, rs1, rd)
  <-> 0b0010001 @ 0b0 @ encdec_vcap(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

function clause execute VEDA_CSEAL(rs2, rs1, rd) = {
  let cs1idx = vcapidx_to_vcapno(rs1);
  let cs2idx = vcapidx_to_vcapno(rs2);
  let cs1 = C(cs1idx);
  let cs2 = C(cs2idx);
  // Authorization: cs2 must be a live, unsealed, Permit_Seal-carrying
  // capability whose own Offset (the value about to become cs1's new
  // otype) lies within cs2's own bounds and isn't a reserved sentinel.
  // Minimal OS kernel Milestone B: the `!= VEDA_OTYPE_SENTRY` exclusion is
  // the load-bearing security property for the whole sentry mechanism --
  // real CHERI's own CSeal enforces the identical kind of bound
  // (`cursor <= cap_max_otype`, CHERI ISA spec p.214) so that ordinary,
  // software-directed sealing can never forge a hardware-reserved otype.
  // Without this line, a capability sealed here with otype=0xFFFE would be
  // indistinguishable from a genuine VEDA_CSEALENTRY-minted sentry to
  // every downstream consumer (VEDA_OCRETURN), defeating the mechanism
  // entirely.
  // Phase 1 increment 2: Offset widened to 40 bits while otype stayed 16,
  // so the requested otype no longer type-matches. A naive [15..0]
  // truncation here would REINTRODUCE sentinel forgery -- Offset 0x1FFFF
  // would alias UNSEALED_OTYPE (0xFFFF) and 0x1FFFE would forge
  // VEDA_OTYPE_SENTRY (0xFFFE), i.e. exactly the sentry-forgery hole the
  // Minimal-OS-kernel Milestone B closed. So an explicit REPRESENTABILITY
  // guard comes first (real CHERI's own `cursor <= cap_max_otype` bound),
  // and only a representable Offset is narrowed into an otype.
  let otype_req : bits(16) = cs2.Offset[15..0];
  let authorized : bool =
    CTag(cs2idx) & not(isSealedCap(cs2)) & permBit(cs2.Perms, PERM_SEAL)
    & (unsigned(cs2.Offset) < unsigned(cs2.Length))
    & (unsigned(cs2.Offset) <= 65535)  // 0xFFFF as an int: `unsigned` yields int, and a 0xFFFF literal is bits(16)
    & (otype_req != UNSEALED_OTYPE)
    & (otype_req != VEDA_OTYPE_SENTRY);
  // An already-untagged or already-sealed cs1 can't be (re-)sealed --
  // "if cs1 was already sealed" from the spec text, plus the same
  // untagged-source-can't-produce-a-valid-result reasoning already
  // applied to OCA above.
  let ok : bool = authorized & CTag(cs1idx) & not(isSealedCap(cs1));
  let new_cap : capability = struct {
    Object_ID = cs1.Object_ID,
    Base      = cs1.Base,
    Length    = cs1.Length,
    Offset    = cs1.Offset,
    Perms     = cs1.Perms,
    otype     = otype_req,
    generation = cs1.generation,
    flags      = cs1.flags,
  };
  let rdno = vcapidx_to_vcapno(rd);
  wC(rdno, new_cap);
  wCTag(rdno, ok);
  RETIRE_SUCCESS
}

function clause execute VEDA_CUNSEAL(rs2, rs1, rd) = {
  let cs1idx = vcapidx_to_vcapno(rs1);
  let cs2idx = vcapidx_to_vcapno(rs2);
  let cs1 = C(cs1idx);
  let cs2 = C(cs2idx);
  // Mirror of CSeal's authorization: cs2 must be live, unsealed,
  // Permit_Unseal-carrying, and its Offset must exactly match cs1's
  // current otype (the type-authority proving it's allowed to unseal
  // *this specific* sealed type), within cs2's own bounds.
  let authorized : bool =
    CTag(cs2idx) & not(isSealedCap(cs2)) & permBit(cs2.Perms, PERM_UNSEAL)
    & isSealedCap(cs1) & (cs2.Offset == zero_extend(cs1.otype))
    & (unsigned(cs2.Offset) < unsigned(cs2.Length));
  let ok : bool = authorized & CTag(cs1idx);
  let new_cap : capability = struct {
    Object_ID = cs1.Object_ID,
    Base      = cs1.Base,
    Length    = cs1.Length,
    Offset    = cs1.Offset,
    Perms     = cs1.Perms,
    otype     = UNSEALED_OTYPE,
    generation = cs1.generation,
    flags      = cs1.flags,
  };
  let rdno = vcapidx_to_vcapno(rd);
  wC(rdno, new_cap);
  wCTag(rdno, ok);
  RETIRE_SUCCESS
}

mapping clause assembly = VEDA_CSEAL(rs2, rs1, rd)
  <-> "cseal" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ vcap_name(encdec_vcap(rs2))

mapping clause assembly = VEDA_CUNSEAL(rs2, rs1, rd)
  <-> "cunseal" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ vcap_name(encdec_vcap(rs2))

// CSealEntry (minimal OS kernel Milestone B, MINIMAL_OS_KERNEL_DESIGN.md):
// term-for-term adaptation of real CHERI's own CSealEntry (CHERI ISA spec
// p.215, `7.4 CHERI-RISC-V INSTRUCTIONS: CSealEntry`, read in full): cd =
// cs1 sealed with the fixed VEDA_OTYPE_SENTRY constant -- no authorizing
// capability operand at all, unlike CSeal/CUnseal above, matching the real
// spec's own description of sentry-minting as "an ambient monotonic
// action, requiring no additional permission than to have a capability
// bearing Permit_Execute" (p.101). Perms (including Permit_Execute) are
// carried through unchanged, neither stripped nor added -- whoever mints a
// sentry is responsible for minting it from an already-executable
// capability, since VEDA_OCRETURN (below) is what actually enforces
// Permit_Execute, at the point of use, exactly matching real CHERI's own
// division of labor between CSealEntry and CJALR.
union clause instruction = VEDA_CSEALENTRY : (vcapidx, vcapidx)

// funct7 = 0010101, the next free Custom-2/funct3=001 slot (verified by
// grep against every existing user of this space before picking it: OCA=
// 0001010, CSeal=0010000, CUnseal=0010001, OCInvoke=0010010, OSpecialRW=
// 0010011, OCJALR=0010100). rs2 is hardwired to all-zero, the same
// established convention OSpecialRW's own unused operand slot already
// uses, since CSealEntry takes only one source capability operand.
mapping clause encdec = VEDA_CSEALENTRY(rs1, rd)
  <-> 0b0010101 @ 0b00000 @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

function clause execute VEDA_CSEALENTRY(rs1, rd) = {
  let cs1idx = vcapidx_to_vcapno(rs1);
  let cs1 = C(cs1idx);
  // An already-sealed or untagged cs1 can't produce a valid sentry -- the
  // same "untagged/already-sealed source can't produce a valid result"
  // reasoning CSeal above already applies, mirroring real CSealEntry's own
  // `clearTagIfSealed` step.
  let ok : bool = CTag(cs1idx) & not(isSealedCap(cs1));
  let new_cap : capability = struct {
    Object_ID = cs1.Object_ID,
    Base      = cs1.Base,
    Length    = cs1.Length,
    Offset    = cs1.Offset,
    Perms     = cs1.Perms,
    otype     = VEDA_OTYPE_SENTRY,
    generation = cs1.generation,
    flags      = cs1.flags,
  };
  let rdno = vcapidx_to_vcapno(rd);
  wC(rdno, new_cap);
  wCTag(rdno, ok);
  RETIRE_SUCCESS
}

mapping clause assembly = VEDA_CSEALENTRY(rs1, rd)
  <-> "csealentry" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1))

// OCInvoke (VEDA_CORE_SPEC.md Section 6 item 7, now closed): Veda-Core's
// term-for-term adaptation of CHERI's real CInvoke (verified, CHERI ISA
// spec p.209, `7.4 CHERI-RISC-V INSTRUCTIONS: CInvoke`, read in full
// before writing this, not assumed from the Chapter 3 overview alone).
// funct7 = 0010010, the next unused Custom-2 slot after CSeal(0010000)/
// CUnseal(0010001). Real CHERI encodes CInvoke's own two capability
// operands as cs1 (code)/cs2 (data), with NO destination operand at all
// (its outputs, PCC and C31, are architecturally fixed, not
// instruction-selectable) -- Veda-Core mirrors this exactly: rs1 (code
// cap, instr[18:15]) and rs2 (data cap, instr[23:20]) are the only real
// operands; the rd field (instr[11:7]) is reserved, required to encode
// as 0, matching this file's own established "dest-kind" funct3=001
// R-type shape used by OCA/CSetBounds/CSeal/CUnseal but with no actual
// destination register consumed.
union clause instruction = VEDA_OCINVOKE : (vcapidx, vcapidx)

mapping clause encdec = VEDA_OCINVOKE(rs2, rs1)
  <-> 0b0010010 @ 0b0 @ encdec_vcap(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ 0b0000 @ 0b1011011
  when currentlyEnabled(Ext_Veda)

// Fixed architectural target for the unsealed data capability -- CHERI's
// own real C31 (the last register in its 32-entry capability register
// file, GPR-overlaid) adapted proportionally to Veda-Core's own smaller,
// 16-entry, non-GPR-overlaid Capability Register File: c15, the last
// entry. A software ABI convention, not a hardware-enforced lock --
// CHERI's own C31/IDC is the identical kind of convention, not a
// separate physical register either (confirmed directly from the
// semantics below: `C(31) = unsealCap(cs2_val)` writes through the
// ordinary capability register file, index 31, nothing more).
let VEDA_IDC_INDEX : vcapno = Vcapno(15)

// Milestone 10's own original scope deviation from real CHERI is
// PARTIALLY closed as of Milestone 14
// (rva23-core/veda-core/PCC_COMPARTMENT_DESIGN.md): CHERI's own CInvoke
// installs the unsealed CODE capability into PCC (a full capability
// struct, later inspectable via CGetPCC, and consumed by every
// subsequent instruction fetch for bounds/permission enforcement).
// Veda-Core still has no full PCC struct (Object_ID/Perms/otype/
// Reserved are not tracked for the active compartment, only what
// PCC_COMPARTMENT_DESIGN.md's own research found this project actually
// needed a real consumer for: Base/Length, real fetch-time bounds
// enforcement via core/addr_checks.sail's own overridden
// `ext_fetch_check_pc`) -- this pass narrows `veda_pcc_base`/
// `veda_pcc_length` to `cs1`'s own bounds on every successful
// invocation, so code entered via `OCInvoke` genuinely cannot execute
// (or return control) outside the region it was handed authority over,
// the actual security property `CInvoke`/`OCInvoke` exist to provide.
// The resolved target address (Base + Offset, the same real CGetAddr
// semantics already established) still redirects PC directly, achieving
// CHERI's own real "atomic unseal-and-jump" property literally (a true
// hardware jump, not a two-instruction unseal-then-JALR sequence).
function clause execute VEDA_OCINVOKE(rs2, rs1) = {
  let cs1idx = vcapidx_to_vcapno(rs1);
  let cs2idx = vcapidx_to_vcapno(rs2);
  let cs1 = C(cs1idx);
  let cs2 = C(cs2idx);
  // Exact CHERI check order (ISA spec p.209), term-for-term: Tag(cs1) ->
  // Tag(cs2) -> Seal(cs1) -> Seal(cs2) -> matching otype -> Permit_Invoke
  // (cs1) -> Permit_Invoke(cs2) -> Permit_Execute(cs1) must hold ->
  // Permit_Execute(cs2) must NOT hold (data capability must be
  // non-executable). CHERI's own trailing PCC-relocation/fetch-alignment/
  // fetch-bounds checks are omitted -- they exist solely to validate a
  // PCC this pass deliberately never stores, per the comment above, so
  // there is nothing for them to validate here.
  if not(CTag(cs1idx)) then veda_trap(rs1, VEDA_CAUSE_TAG_VIOLATION)
  else if not(CTag(cs2idx)) then veda_trap(rs2, VEDA_CAUSE_TAG_VIOLATION)
  else if not(isSealedCap(cs1)) then veda_trap(rs1, VEDA_CAUSE_SEAL_VIOLATION)
  else if not(isSealedCap(cs2)) then veda_trap(rs2, VEDA_CAUSE_SEAL_VIOLATION)
  else if cs1.otype != cs2.otype then veda_trap(rs1, VEDA_CAUSE_TYPE_VIOLATION)
  else if not(permBit(cs1.Perms, PERM_INVOKE)) then veda_trap(rs1, VEDA_CAUSE_PERM_INVOKE_VIOLATION)
  else if not(permBit(cs2.Perms, PERM_INVOKE)) then veda_trap(rs2, VEDA_CAUSE_PERM_INVOKE_VIOLATION)
  else if not(permBit(cs1.Perms, PERM_EXECUTE)) then veda_trap(rs1, VEDA_CAUSE_PERM_EXECUTE_VIOLATION)
  else if permBit(cs2.Perms, PERM_EXECUTE) then veda_trap(rs2, VEDA_CAUSE_PERM_EXECUTE_VIOLATION)
  else {
    let unsealed_cs2 : capability = struct {
      Object_ID = cs2.Object_ID,
      Base      = cs2.Base,
      Length    = cs2.Length,
      Offset    = cs2.Offset,
      Perms     = cs2.Perms,
      otype     = UNSEALED_OTYPE,
      generation = cs2.generation,
      flags      = cs2.flags,
    };
    wC(VEDA_IDC_INDEX, unsealed_cs2);
    wCTag(VEDA_IDC_INDEX, true);
    // Milestone 14: narrow the live compartment to cs1's own bounds --
    // the real security effect real CHERI's own PCC-installation
    // achieves, applied to the Base/Length subset this project's own
    // research found a real consumer for (PCC_COMPARTMENT_DESIGN.md §7:
    // Perms-on-PCC deliberately deferred, no real consumer exists yet).
    // Phase 1 increment 2 scope note: the CAPABILITY widened, but the PCC
    // compartment registers deliberately did NOT, so the bounds are
    // narrowed back here. This is provably LOSSLESS in this increment --
    // every capability's Base/Length originates from the ODT, whose own
    // entry is still Base(32)/Length(16) -- so it reproduces the previous
    // model's behaviour exactly, which is what keeps the verified test
    // baseline meaningful rather than merely passing. PCC widens in the
    // SAME increment that widens the ODT entry (that is when values wider
    // than these can first exist); the VEDA_PCC_UNBOUNDED sentinel changes
    // value at that point, which is why it is deliberately not done here.
    veda_pcc_base = cs1.Base[31..0];
    veda_pcc_length = cs1.Length[15..0];
    // SSC (Stack-Spill Capability, see veda_types.sail's veda_scr enum):
    // clear (untag) on every successful invoke, unconditionally -- a
    // hardware guarantee, not a software discipline, the identical real
    // lesson Milestone 17/OCJALR already taught this project once
    // (STACK_FRAME_CALL_RETURN_ANALYSIS.md). Without this, the entered
    // compartment would silently inherit full OCL.D/OCS.D read/write
    // access to whatever stack region the invoking context had bound --
    // a real confidentiality/integrity leak an independent design review
    // found before any code was written: applying ODA/TSC's own
    // "untouched by OCInvoke" convention to SSC would have left the
    // caller's entire stack region reachable from the callee. Clearing
    // only the Tag (not zeroing the value) matches this project's own
    // established convention (Milestone 7's tag-clearing-on-plain-write)
    // -- any OCL.D/OCS.D against an untagged capability already hard-traps
    // regardless of the stale bits underneath. The entered compartment is
    // responsible for establishing its own SSC via an explicit
    // OSpecialRW, the identical already-established pattern ODA/TSC
    // themselves use -- no new operand, no encoding change, symmetric
    // with the identical clear this milestone also adds to OCRETURN
    // below (return is a real compartment-boundary crossing too; the
    // same leak class applies in that direction as well).
    veda_ssc_tag = false;
    let target : xlenbits = veda_to_xlen(zero_extend(cs1.Base) + zero_extend(cs1.Offset));
    jump_to([target with 0 = bitzero])
  }
}

mapping clause assembly = VEDA_OCINVOKE(rs2, rs1)
  <-> "ocinvoke" ^ spc() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ vcap_name(encdec_vcap(rs2))

// OCJALR (STACK_FRAME_CALL_RETURN_ANALYSIS.md): the real, honest gap that
// analysis found by testing rather than assuming -- a return-address
// convention built entirely from already-existing instructions (a
// long-lived stack-object capability, `OCA` to derive a return-capability,
// `CSeal` to protect it) worked when the caller *remembered* an explicit
// `CGetTag` check before using the reloaded value, but nothing stopped
// the check from being silently omitted: `CUnseal`+`CGetAddr`+`JALR`
// compose into a working (if undefined-on-corruption) jump with no
// hardware gate at all. `OCJALR` closes that specific gap: it merges
// unseal-verification and jump into one atomic instruction, so the check
// cannot be forgotten by construction, the same real property real
// CHERI's own `CJALR` provides for its own sentry-capability jumps
// (`CapEx_SealViolation` on a sealed-but-wrong capability, CHERI ISA spec
// p.213, `7.4 CHERI-RISC-V INSTRUCTIONS: CJALR`, full semantics read).
//
// Deliberately narrower than real CHERI's own `CJALR`, not a full port:
// real `CJALR` is a general jump-through-any-capability instruction (used
// for ordinary calls too) that also *mints* a new sentry-sealed return
// capability as a side effect of every jump, using a dedicated reserved
// `otype` sentinel distinct from `CSeal`'s general type-authority
// mechanism. `OCJALR` here is scoped to exactly the half the
// vulnerability was in -- the *verify-and-consume* side of an
// already-sealed return-capability -- reusing Milestone 6's existing,
// already-verified general-purpose `CSeal`/`CUnseal` type-authority model
// (the call site already works today, unmodified, via `OCA`+`CSeal`) so
// no second, parallel sealing mechanism needs to be invented for this one
// purpose. `rd` is reserved and unused, matching `OCInvoke`'s own
// established precedent for an instruction whose real output is a PC
// redirect, not a register value.
union clause instruction = VEDA_OCJALR : (vcapidx, vcapidx)

// funct7 = 0010100, the next genuinely unused Custom-2/funct3=001 slot --
// verified directly against every existing user of this space before
// picking it (OCA=0001010, CSeal=0010000, CUnseal=0010001,
// OCInvoke=0010010, OSpecialRW=0010011 -- 0010011 was this instruction's
// own first draft value, caught as a real, narrow encoding collision with
// the already-existing OSpecialRW before any RTL was written: OSpecialRW
// hardwires its own rs2-position field to all-zero rather than treating
// it as a real operand, so the collision would only have bitten a
// subset of encodings -- OCJALR instances with cs2 = c0 -- rather than
// failing every test immediately, exactly the kind of narrow, easy-to-
// miss bug this project's "verify before deciding" discipline exists to
// catch before it ships).
mapping clause encdec = VEDA_OCJALR(rs2, rs1)
  <-> 0b0010100 @ 0b0 @ encdec_vcap(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ 0b0000 @ 0b1011011
  when currentlyEnabled(Ext_Veda)

// rs1 = the (possibly-corrupted) sealed return-capability being verified
// and jumped through; rs2 = the same seal-authority capability the call
// site's own `CSeal` used. Check order chosen to match real, established
// precedent rather than invented fresh: `Seal Violation` (cause 0x03) is
// VEDA_CORE_SPEC.md's own already-verified mapping for exactly this
// condition on real CHERI's `CJALR` (Section 3 of the spec cites this
// directly); `Type Violation` (0x04) and `Permit_Execute Violation`
// (0x11) reuse `OCInvoke`'s own already-active checks for the identical
// underlying conditions (authority mismatch, missing execute permission).
function clause execute VEDA_OCJALR(rs2, rs1) = {
  let cs1idx = vcapidx_to_vcapno(rs1);
  let cs2idx = vcapidx_to_vcapno(rs2);
  let cs1 = C(cs1idx);
  let cs2 = C(cs2idx);
  if not(CTag(cs1idx)) then veda_trap(rs1, VEDA_CAUSE_TAG_VIOLATION)
  else if not(CTag(cs2idx)) then veda_trap(rs2, VEDA_CAUSE_TAG_VIOLATION)
  else if not(isSealedCap(cs1)) then veda_trap(rs1, VEDA_CAUSE_SEAL_VIOLATION)
  else if isSealedCap(cs2) then veda_trap(rs2, VEDA_CAUSE_SEAL_VIOLATION)
  else if not(permBit(cs2.Perms, PERM_UNSEAL)) then veda_trap(rs2, VEDA_CAUSE_SEAL_VIOLATION)
  else if cs2.Offset != zero_extend(cs1.otype) then veda_trap(rs1, VEDA_CAUSE_TYPE_VIOLATION)
  else if not(permBit(cs1.Perms, PERM_EXECUTE)) then veda_trap(rs1, VEDA_CAUSE_PERM_EXECUTE_VIOLATION)
  else {
    let target : xlenbits = veda_to_xlen(zero_extend(cs1.Base) + zero_extend(cs1.Offset));
    jump_to([target with 0 = bitzero])
  }
}

mapping clause assembly = VEDA_OCJALR(rs2, rs1)
  <-> "ocjalr" ^ spc() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ vcap_name(encdec_vcap(rs2))

// OCRETURN (minimal OS kernel Milestone B, MINIMAL_OS_KERNEL_DESIGN.md):
// the actual cheap, cross-compartment-boundary-crossing counterpart to
// OCJALR's own verify-and-consume-only, always-two-operand design above.
// Deliberately a NEW opcode rather than a sentry branch folded into
// OCJALR: OCJALR's own `rs2` is a fixed encoding field (folding a branch
// in would either still require `rs2` to be supplied unused, defeating
// the single-operand premise, or make one static encoding mean two
// different things depending on runtime capability contents -- this
// project's own convention already gives each distinct security-relevant
// behavior its own funct7, e.g. OCA/CSetBounds/CSetBoundsExact, rather
// than overloading one opcode's meaning by capability content). OCJALR
// itself is completely unmodified by this instruction's addition --
// direct, load-bearing preservation of RTL Milestone 22's own already-
// shipped, already-tested "OCJALR cannot cross a compartment boundary"
// finding.
//
// `cs1` must be a genuine VEDA_CSEALENTRY-minted sentry (otype ==
// VEDA_OTYPE_SENTRY, a value ordinary CSeal is now hardware-blocked from
// ever producing, per the hardened VEDA_CSEAL authorization above) --
// verified with exactly the same three checks OCJALR's own cs1-side
// already performs (tag, seal-validity, Permit_Execute), reusing the
// identical cause codes, but with NO second, type-authority capability
// operand at all: a sentry's own otype is self-authenticating, unlike an
// arbitrary CSeal otype which always needs an explicit CUnseal-style
// authority to vouch for it. Permit_Invoke is deliberately NOT checked --
// matches real CHERI's own sentry/CJALR mechanism exactly (invoke-
// permission is CInvoke-specific; sentries are a lighter-weight,
// separate mechanism with no data-capability handoff).
//
// On success, narrows `veda_pcc_base`/`veda_pcc_length` to cs1's own
// Base/Length -- the actual compartment-boundary-crossing side effect,
// mirroring OCInvoke's own identical assignment above verbatim, in the
// same narrow-then-jump order OCInvoke already established (not
// re-derived fresh) -- before computing `target` and jumping. `IDC`/c15
// is deliberately left untouched (not cleared): real CJALR never touches
// IDC either (only CInvoke does), and OCInvoke's own code above already
// treats "install data-capability context" and "narrow PCC" as two
// independently-triggered effects, so OCRETURN adopting only the PCC
// half reuses a split this codebase already makes internally rather than
// inventing a new one. Security property, stated explicitly: OCRETURN's
// guarantee is identical in kind to OCInvoke's -- bounded by whatever
// capability the caller already legitimately possesses (valid tag,
// genuine Permit_Execute, and an otype only ever produced by minting,
// never by forgery) -- it is a cheaper mechanism for exercising
// pre-existing authority, not a new source of authority.
union clause instruction = VEDA_OCRETURN : (vcapidx)

// funct7 = 0010110, the next free Custom-2/funct3=001 slot after
// CSealEntry's own 0010101 above (verified by grep against every existing
// user of this space before picking it). rs2 and rd are both hardwired to
// all-zero -- OCRETURN takes exactly one source capability operand and,
// like OCInvoke/OCJALR above, its real output is a PC redirect (plus the
// PCC-narrowing side effect), not a register value.
mapping clause encdec = VEDA_OCRETURN(rs1)
  <-> 0b0010110 @ 0b00000 @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ 0b0000 @ 0b1011011
  when currentlyEnabled(Ext_Veda)

function clause execute VEDA_OCRETURN(rs1) = {
  let cs1idx = vcapidx_to_vcapno(rs1);
  let cs1 = C(cs1idx);
  if not(CTag(cs1idx)) then veda_trap(rs1, VEDA_CAUSE_TAG_VIOLATION)
  else if not(isSealedCap(cs1)) then veda_trap(rs1, VEDA_CAUSE_SEAL_VIOLATION)
  else if cs1.otype != VEDA_OTYPE_SENTRY then veda_trap(rs1, VEDA_CAUSE_SEAL_VIOLATION)
  else if not(permBit(cs1.Perms, PERM_EXECUTE)) then veda_trap(rs1, VEDA_CAUSE_PERM_EXECUTE_VIOLATION)
  else {
    // Phase 1 increment 2 scope note: the CAPABILITY widened, but the PCC
    // compartment registers deliberately did NOT, so the bounds are
    // narrowed back here. This is provably LOSSLESS in this increment --
    // every capability's Base/Length originates from the ODT, whose own
    // entry is still Base(32)/Length(16) -- so it reproduces the previous
    // model's behaviour exactly, which is what keeps the verified test
    // baseline meaningful rather than merely passing. PCC widens in the
    // SAME increment that widens the ODT entry (that is when values wider
    // than these can first exist); the VEDA_PCC_UNBOUNDED sentinel changes
    // value at that point, which is why it is deliberately not done here.
    veda_pcc_base = cs1.Base[31..0];
    veda_pcc_length = cs1.Length[15..0];
    // SSC: clear on every successful return too, the identical reason and
    // identical mechanism as VEDA_OCINVOKE above -- OCRETURN is a real,
    // general compartment-boundary crossing (not only used inside the
    // scheduler's own switcher pattern), so the same hardware guarantee
    // must hold unconditionally here as well, not just on the call side.
    veda_ssc_tag = false;
    let target : xlenbits = veda_to_xlen(zero_extend(cs1.Base) + zero_extend(cs1.Offset));
    jump_to([target with 0 = bitzero])
  }
}

mapping clause assembly = VEDA_OCRETURN(rs1)
  <-> "ocreturn" ^ spc() ^ vcap_name(encdec_vcap(rs1))

// OSpecialRW (VEDA_CORE_SPEC.md Section 6 item 8, formerly NEXT_STEPS_
// ROADMAP.md §2.5): term-for-term adaptation of real CHERI's own
// CSpecialRW (CHERI ISA spec §4.3.6/p.235), reading and writing one of
// Veda-Core's own Special Capability Registers -- the ODA (Object
// Descriptor Authority, Milestone 11) or, as of Minimal OS kernel
// Milestone A, the TSC (Trusted Stack Capability). funct7 = 0010011, the
// next unused Custom-2 slot after OCInvoke (0010010). Real CHERI's own
// access rule for SCR writes (Table 4.3's "ASR" column): the current
// mode must be permitted AND PCC.perms must grant
// PERMIT_ACCESS_SYSTEM_REGISTERS. Veda-Core has no PCC (Milestone 10's
// own deliberate scope boundary), so this is gated on ordinary
// privilege alone (cur_privilege == Machine) -- the identical, already-
// established convention ODT_POPULATE/ODT_DESTROY themselves use, not a
// new one invented for this instruction specifically.
//
// Minimal OS kernel Milestone A: the field that was previously
// hardcoded `00000` (real CHERI's own `CSpecialRW cd, scr, cs1` already
// has a genuine SCR-index operand in exactly this position -- Veda-Core
// simply never needed it before, with only one real SCR to select)
// becomes a real `veda_scr` selector. Chosen encoding value for ODA
// (0b00000) is byte-for-byte identical to every `ospecialrw` encoding
// this codebase has ever produced, so this is a real, verified backward
// -compatible extension, not a breaking change to an existing
// instruction -- confirmed by construction, not merely assumed.
union clause instruction = VEDA_OSPECIALRW : (veda_scr, vcapidx, vcapidx)

mapping encdec_veda_scr : veda_scr <-> bits(5) = {
  VEDA_SCR_ODA <-> 0b00000,
  VEDA_SCR_TSC <-> 0b00001,
  VEDA_SCR_SSC <-> 0b00010,
}

mapping clause encdec = VEDA_OSPECIALRW(scr, rs1, rd)
  <-> 0b0010011 @ encdec_veda_scr(scr) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

function clause execute VEDA_OSPECIALRW(scr, rs1, rd) = {
  if cur_privilege != Machine then Illegal_Instruction()
  else {
    let rdno = vcapidx_to_vcapno(rd);
    let rs1no = vcapidx_to_vcapno(rs1);
    // Real CHERI's own CSpecialRW semantics, unabridged: cd receives the
    // SCR's OLD value first, THEN the SCR is overwritten with cs1 -- a
    // real atomic read-then-write, not two independent operations (this
    // matters if rs1 == rd: the old SCR value must still be correctly
    // captured before it's overwritten). Identical discipline for both
    // real SCRs -- only which register pair is touched differs.
    match scr {
      VEDA_SCR_ODA => {
        let old_oda = veda_oda;
        let old_tag = veda_oda_tag;
        C(rdno) = old_oda;
        CTag(rdno) = old_tag;
        veda_oda = C(rs1no);
        veda_oda_tag = CTag(rs1no);
      },
      VEDA_SCR_TSC => {
        let old_tsc = veda_tsc;
        let old_tag = veda_tsc_tag;
        C(rdno) = old_tsc;
        CTag(rdno) = old_tag;
        veda_tsc = C(rs1no);
        veda_tsc_tag = CTag(rs1no);
      },
      VEDA_SCR_SSC => {
        let old_ssc = veda_ssc;
        let old_tag = veda_ssc_tag;
        C(rdno) = old_ssc;
        CTag(rdno) = old_tag;
        veda_ssc = C(rs1no);
        veda_ssc_tag = CTag(rs1no);
      },
    };
    RETIRE_SUCCESS
  }
}

mapping veda_scr_name : veda_scr <-> string = {
  VEDA_SCR_ODA <-> "oda",
  VEDA_SCR_TSC <-> "tsc",
  VEDA_SCR_SSC <-> "ssc",
}

mapping clause assembly = VEDA_OSPECIALRW(scr, rs1, rd)
  <-> "ospecialrw" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ veda_scr_name(scr) ^ sep() ^ vcap_name(encdec_vcap(rs1))

// CAndPerm (Phase 1, DESIGN_01 "New instruction -- CAndPerm"): per-holder
// monotonic rights attenuation -- cd = cs1 with Perms &= rs2 (a GPR-held
// mask). Same R-type shape as OCA (rs2 = GPR, rs1/rd = Capability Register).
//
// funct7 = 0010111, the next free Custom-2/funct3=001 slot after OCRETURN's
// 0010110 -- verified by full enumeration of this file before picking it
// (OCA=0001010, CSetBounds=0001000, CSetBoundsExact=0001001, CSeal=0010000,
// CUnseal=0010001, OCInvoke=0010010, OSpecialRW=0010011, OCJALR=0010100,
// CSealEntry=0010101, OCRETURN=0010110), the same "next free slot, grep
// first" discipline OCJALR/CSealEntry/OCRETURN each used.
//
// Why this instruction exists (DESIGN_01): without per-holder attenuation,
// giving a domain a read-only view of a live object forces a SEPARATE
// Object_ID aliasing the same Base -- which breaks temporal safety
// (destroying one ID does not revoke the alias). CAndPerm derives a weaker
// capability to the SAME live object (no new Object_ID, no aliasing), so a
// later ODT-Destroy still revokes every view. Essential for the multi-
// process rights model (read-only text/data shared to children).
union clause instruction = VEDA_CANDPERM : (regidx, vcapidx, vcapidx)

mapping clause encdec = VEDA_CANDPERM(rs2, rs1, rd)
  <-> 0b0010111 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b001 @ 0b0 @ encdec_vcap(rd) @ 0b1011011
  when currentlyEnabled(Ext_Veda)

// Semantics: bitwise AND is monotonic clear-only -- it can never GRANT a
// permission, only remove one, so the result is unconditionally a subset of
// cs1's rights by construction (no separate subset check needed). Soft-fail
// exactly like the OCA/CSetBounds manipulate family: cd's fields are always
// written, and the Tag is conditionally cleared -- here on an untagged or
// already-sealed cs1 (a sealed capability's rights are frozen; an untagged
// source can never produce a valid result, the same reasoning OCA applies).
// No bounds term (unlike OCA/CSetBounds): masking Perms cannot produce an
// out-of-window value, so the only soft-fail conditions are tag+seal.
function clause execute VEDA_CANDPERM(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let cap = C(capidx);
  let mask : xlenbits = X(rs2);
  // Perms is bits(16) (veda_types.sail); AND with the low 16 mask bits.
  let new_perms : bits(16) = cap.Perms & mask[15 .. 0];
  let new_cap : capability = struct {
    Object_ID = cap.Object_ID,
    Base      = cap.Base,
    Length    = cap.Length,
    Offset    = cap.Offset,
    Perms     = new_perms,
    otype     = cap.otype,
    generation = cap.generation,
    flags      = cap.flags,
  };
  let rdno = vcapidx_to_vcapno(rd);
  wC(rdno, new_cap);
  wCTag(rdno, CTag(capidx) & not(isSealedCap(cap)));
  RETIRE_SUCCESS
}

mapping clause assembly = VEDA_CANDPERM(rs2, rs1, rd)
  <-> "candperm" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)
