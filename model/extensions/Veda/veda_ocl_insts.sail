// Veda-Core formal model: OCL.D / OCS.D (VEDA_CORE_SPEC.md Section 1).
//
// Milestone V-A scope only (FORMAL_VERIFICATION_PLAN.md): the 64-bit
// (funct3 = 0b011, "D") width only, no NMC_ADD, no Veda-Atomic, no
// sealing/query/OCA instructions yet -- those are Milestone V-B.
//
// R-type, Custom-0 opcode (0b0001011), funct7 selects OCL (0b0000000) vs
// OCS (0b0000001) -- distinct from Object-Bind's I-type encoding via
// funct3 != 0b101.
//
// Operand convention, resolved while writing this file (not previously
// spelled out this precisely in VEDA_CORE_SPEC.md Section 1): `rs2` is
// always the GPR-held per-access offset, for both OCL and OCS, keeping its
// role uniform across the pair -- matching the "rs2 = a GPR-held offset
// for this access only" wording already in Section 1 (unqualified by
// OCL/OCS). Since R-type has no third free source-register slot, `rd` is
// read (not written) as the store-value source for OCS -- the only
// register position left once `rs1` is committed to the capability and
// `rs2` to the offset. Kept distinct from Veda-Atomic (Section 1), whose
// `rs1` capability "must already point at the exact target location" via
// its own persistent `Offset` field precisely because Veda-Atomic's `rs2`
// is already committed to the value operand, leaving no register free for
// a fresh offset -- OCL/OCS don't have that constraint, since neither
// needs a "old value" destination the way Veda-Atomic does.

union clause instruction = VEDA_OCL : (regidx, vcapidx, regidx)
union clause instruction = VEDA_OCS : (regidx, vcapidx, regidx)

// `when xlen == 64`, mirroring extensions/I/base_insts.sail's own real
// ADDIW/RTYPEW instructions (RV64-only): OCL.D/OCS.D read/write exactly
// xlen_bytes (8 on RV64), which only fits `xlenbits` when xlen == 64.
mapping clause encdec = VEDA_OCL(rs2, rs1, rd)
  <-> 0b0000000 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b011 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

mapping clause encdec = VEDA_OCS(rs2, rs1, rd)
  <-> 0b0000001 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b011 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

// Shared "use" checks (VEDA_CORE_SPEC.md Section 1, "Sealed-capability
// enforcement"): Tag Violation and Seal Violation are hard traps for OCL/
// OCS (they dereference the object), unlike OCA/CSetBounds's soft-fail
// (Milestone V-B). Returns the real physical location on success.
// `offset`/`real_loc` are `xlenbits`, not a hardcoded `bits(64)` -- a real
// build error (physaddrbits is `bits(34)` on RV32, `bits(64)` on RV64;
// zero-extending a fixed bits(64) into a possibly-34-bit target doesn't
// typecheck) showed the hardcoded width was wrong. `xlenbits` is what
// `X()` actually returns and what the real base-ISA LOAD/STORE code uses
// for the same purpose (extensions/I/base_insts.sail), confirmed before
// making this fix, not assumed.
// Real gap found and fixed in Milestone V-B: VEDA_CORE_SPEC.md Section 5.1
// requires the generation counter to be "re-checked by the MSA on every
// dereference" to detect a capability that's gone stale (its Object_ID
// was freed and reallocated to a different object since this capability
// register was bound) -- V-A's own version of this function never did
// that re-check, only validating fields already cached locally in the
// capability register. Fixed here by looking the ODT entry up fresh on
// every call and comparing its live `generation` against the capability's
// own cached copy (`cap.Reserved`, populated by Object-Bind) -- a mismatch
// (or the entry no longer being `valid` at all, i.e. the object was
// destroyed and not yet replaced) is treated as a Tag Violation, matching
// the spec's own words exactly ("mismatch -> Tag Violation", Section 5.1).
function veda_check_access(capidx : vcapno, offset : xlenbits, width : int, need_load : bool, need_store : bool, check_align : bool) -> result(physaddr, ExecutionResult) = {
  let cap = C(capidx);
  let entry = odt_lookup(cap.Object_ID);
  // R19 increment 1: hoisted out of the Ok branch, because the alignment arm
  // below now lives INSIDE this chain and needs the resolved address. It reads
  // only cap.Base and offset, both available before the entry is consulted, so
  // hoisting introduces no ordering hazard. Phase 1 increment 2: Base is 56
  // bits, so the sum is computed in an explicit 64-bit domain and narrowed once
  // via veda_to_xlen (DESIGN_01 decision 7: Ext_Veda is RV64-only, and the
  // encdec's own xlen==64 guard is deliberately not visible to the type checker
  // inside an execute body).
  let real_loc64 : bits(64) = zero_extend(cap.Base) + zero_extend(offset);
  if not(CTag(capidx)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if not(entry.valid) | entry.generation != cap.generation then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if isSealedCap(cap) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_SEAL_VIOLATION))
  else if need_load & not(permBit(cap.Perms, PERM_LOAD)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_LOAD_VIOLATION))
  // R19 increment 1 -- the store-permission arm is GATED on not-cow, and that
  // gate is what lets the copy-on-write arm move to the BOTTOM of this chain.
  //
  // Why the gate is load-bearing and cannot simply be dropped: veda_bind_perms
  // masks a cow object's Perms with 0xFFF7, clearing PERM_STORE (bit 3) and
  // leaving PERM_LOAD (bit 2). So a capability freshly bound to a cow object
  // lacks store permission BY CONSTRUCTION. Without this gate, moving the cow
  // arm below this one would make every fork-triggered write report "you may
  // not write" instead of "copy me", and copy-on-write would never fire at all.
  // The property the previous ordering bought -- a cow object reports 0x0C and
  // never 0x13 -- is preserved exactly, by the gate rather than by precedence.
  //
  // NOTE the premise recorded earlier in this file was too strong: it is not
  // true that EVERY capability to a cow object lacks store. The parent's
  // pre-cow capability retains it (set.cow deliberately does not bump the
  // generation -- that is the fork case), and both are handled here: the parent
  // skips this arm because it HAS store, the child skips it because of the gate.
  else if need_store & not(permBit(cap.Perms, PERM_STORE)) & not(entry.cow) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_STORE_VIOLATION))
  // R19 increment 1 -- 32-byte alignment moved HERE from the OCL.C / OCS.C
  // callers, where it ran AFTER this whole chain returned Ok. Left there, a
  // misaligned store to a cow object would report 0x0C in Sail and 0x08 in the
  // RTL (whose alignment has always been an arm inside the cause chain) -- a
  // divergence created on a state where the two layers agree today. Hoisting
  // also closes two pre-existing divergences nobody had noticed: misaligned +
  // out-of-bounds, and misaligned + non-resident.
  else if check_align & (real_loc64[4 .. 0] != zeros()) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_CAP_MISALIGNED))
  else if unsigned(offset) + width > unsigned(cap.Length) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_BOUNDS_VIOLATION))
  // DESIGN_02 -- OBJECT residency, checked HERE and not only at Bind. This
  // term closes a real hole, and it is free: `entry` is already read above,
  // so it costs no additional ODT access. (Both dereference checkers carry
  // this identically -- keep them textually parallel so they stay diffable.)
  //
  // Why bind-only would be unsound. The address below is computed from
  // `cap.Base` -- the capability's CACHED copy -- never from entry.Base. A
  // page-out that frees this object's frame and reassigns it elsewhere is
  // therefore invisible to this path: `valid` stays true (the object still
  // exists), and `generation` is bumped only by Populate and Destroy, never
  // by paging. So a capability minted while the object was resident and
  // held across a page-out would read and write whatever now occupies that
  // memory. The codebase already records that held-across-page-out state as
  // legal and reachable for regions; for objects it is worse, because it is
  // the contents themselves that moved.
  //
  // The DESIGN_08 region precedent deliberately does NOT transfer. Region
  // residency governs whether a domain's TABLE is paged in -- and by the
  // time control reaches here the capability has already cached everything
  // it needs from that table, so the table's absence changes nothing about
  // this access. Object residency governs the BACKING MEMORY the cached
  // Base points at. Same word, different referent, opposite conclusion.
  //
  // Placed LAST among the entry-derived checks, matching the rule OCInvoke's
  // region gate already established: a capability that is untagged, stale,
  // sealed, unpermitted or out of bounds still reports its own real cause,
  // and RESIDENCY_FAULT is raised only for an access that would otherwise
  // have SUCCEEDED. That is exactly what a resumable pager fault should
  // mean -- page the object in, re-execute, proceed.
  else if not(entry.resident) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_RESIDENCY_FAULT))
  // R19 increment 1 -- COPY-ON-WRITE, now LAST, and still read from the ENTRY.
  //
  // From the entry because set.cow deliberately does not bump the generation,
  // so capabilities minted BEFORE an object became copy-on-write are still live
  // and still carry store permission. A test reading the CAPABILITY would miss
  // exactly those -- the parent's own capability at the moment of fork, the
  // first one that will be written.
  //
  // LAST because 0x0C is not a refusal, it is a REPAIR REQUEST: it instructs a
  // handler to allocate, copy, and hand back a fresh writable object. Raising
  // it for an access that was going to be refused anyway arms that work for
  // nothing. This chain's own residency arm already states the rule -- a repair
  // fault is raised "only for an access that would otherwise have SUCCEEDED" --
  // and the cow arm violated it from the day it landed.
  //
  // BELOW residency specifically, because you cannot copy an object that is not
  // in memory: the handler would dereference a Base whose frame the pager may
  // already have reassigned. Residency is repaired first, and the retry then
  // raises 0x0C.
  //
  // The one amplification this genuinely closes: veda_setbounds with rs2 = 0
  // constructs a tagged, unsealed, generation-current capability of Length 0 in
  // ONE instruction. Under the old order that zero-entitlement capability
  // stored, reached the cow arm before bounds was ever consulted, took 0x0C,
  // and the handler rebound it to a FULL-Length capability minted from the
  // entry. Under this order every offset is out of bounds, so it can never arm
  // a split. Note this is NOT "closing rights amplification" in general -- a
  // principal that can trigger 0x0C out of bounds can trigger it at offset 0
  // and get the same private copy. The rest is ordering hygiene and resource
  // containment, and it should be described as such.
  else if need_store & entry.cow then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_COW_FAULT))
  else {
    // real_loc64 is computed at the top of this function -- see the hoist there.
    let real_loc : xlenbits = veda_to_xlen(real_loc64);
    Ok(Physaddr(zero_extend(real_loc)))
  }
}

function clause execute VEDA_OCL(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let offset : xlenbits = X(rs2);
  match veda_check_access(capidx, offset, xlen_bytes, true, false, false) {
    Err(res) => res,
    Ok(paddr) => {
      let (data, _) : (xlenbits, mem_meta) = read_ram(Read_plain, paddr, xlen_bytes, false);
      X(rd) = data;
      RETIRE_SUCCESS
    },
  }
}

function clause execute VEDA_OCS(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let offset : xlenbits = X(rs2);
  match veda_check_access(capidx, offset, xlen_bytes, false, true, false) {
    Err(res) => res,
    Ok(paddr) => {
      let data = X(rd);
      let _ = write_ram(Write_plain, paddr, xlen_bytes, data, default_meta);
      RETIRE_SUCCESS
    },
  }
}

mapping clause assembly = VEDA_OCL(rs2, rs1, rd)
  <-> "ocl.d" ^ spc() ^ reg_name(rd) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)

mapping clause assembly = VEDA_OCS(rs2, rs1, rd)
  <-> "ocs.d" ^ spc() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2) ^ sep() ^ reg_name(rd)

// OCL.C / OCS.C (VEDA_CORE_SPEC.md's own "OCL.C/OCS.C semantics" writeup,
// Milestone 7): same funct7 (OCL=0000000/OCS=0000001) as OCL.D/OCS.D above,
// differentiated by funct3=100 (the "C" width already reserved in the
// width table since the very first draft of this ISA). The one real,
// decided difference from every other OCL/OCS width: `rd` here is a
// Capability Register (`vcapidx`), not a GPR (`regidx`) -- CHERI's own
// real [C]LC/[C]SC target a capability register for exactly this reason
// (a 128-bit capability plus Tag has no meaningful GPR representation),
// already verified and cited elsewhere in this file/the spec.
union clause instruction = VEDA_OCL_C : (regidx, vcapidx, vcapidx)
union clause instruction = VEDA_OCS_C : (regidx, vcapidx, vcapidx)

mapping clause encdec = VEDA_OCL_C(rs2, rs1, rd)
  <-> 0b0000000 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b100 @ 0b0 @ encdec_vcap(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

mapping clause encdec = VEDA_OCS_C(rs2, rs1, rd)
  <-> 0b0000001 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b100 @ 0b0 @ encdec_vcap(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

// 16 (bytes) = 128 bits, the capability's own real width (VEDA_CORE_SPEC.md
// Section 2) -- reuses veda_check_access unchanged, since bounds/permission/
// tag/seal/generation checking is identical in kind to OCL.D/OCS.D, only
// the access width differs.
function clause execute VEDA_OCL_C(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let offset : xlenbits = X(rs2);
  match veda_check_access(capidx, offset, 32, true, false, true) {
    Err(res) => res,
    Ok(paddr) => {
      // 32-byte natural alignment is architectural as of the 256-bit
      // respec (DESIGN_01 decision 2): one capability must occupy exactly
      // one tag granule, otherwise a plain store could rewrite half a
      // stored capability while the tag the load checks still reads 1.
      // Checked after the capability's own validity checks, so a bad
      // capability still reports its real reason first.
      // R19 increment 1: the 32-byte alignment test moved INTO
      // veda_check_access, where it is ordered against bounds, residency and
      // copy-on-write instead of running after the whole chain returned Ok.
      // read_meta = true (unlike OCL.D/OCS.D's `false` above): this is the
      // one real access kind in this file that actually needs the
      // memory-resident Tag, not just the 256 data bits.
      let (data, tag) : (bits(256), mem_meta) = read_ram(Read_plain, paddr, 32, true);
      let loaded_cap = veda_cap_unpack(data);
      C(rd) = loaded_cap;
      // A capability round-tripped through memory carries whatever Tag the
      // tag store actually recorded for those bytes -- true only if a
      // real OCL.C previously stored a tagged capability there, false for
      // any bytes never written by OCS.C (or overwritten since by a plain
      // OCL/OCS/NMC_ADD/Atomic access, none of which ever set the tag
      // store) -- exactly CHERI's own real "a capability loaded from
      // memory is only as trustworthy as what was genuinely stored there"
      // property, not assumed true just because the load succeeded.
      CTag(rd) = tag;
      RETIRE_SUCCESS
    },
  }
}

function clause execute VEDA_OCS_C(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let offset : xlenbits = X(rs2);
  match veda_check_access(capidx, offset, 32, false, true, true) {
    Err(res) => res,
    Ok(paddr) => {
      // 32-byte natural alignment is architectural as of the 256-bit
      // respec (DESIGN_01 decision 2): one capability must occupy exactly
      // one tag granule, otherwise a plain store could rewrite half a
      // stored capability while the tag the load checks still reads 1.
      // Checked after the capability's own validity checks, so a bad
      // capability still reports its real reason first.
      // R19 increment 1: the 32-byte alignment test moved INTO
      // veda_check_access, where it is ordered against bounds, residency and
      // copy-on-write instead of running after the whole chain returned Ok.
      let store_cap = C(rd);
      let store_tag = CTag(rd);
      let packed : bits(256) = veda_cap_pack(store_cap);
      // The store's own Tag is written to the tag store alongside the 128
      // data bits -- an untagged (CTag(rd)=false) capability register
      // still stores its raw field bits (matching CHERI's own real
      // behavior: storing an invalid capability is legal, it just can't
      // be loaded back as valid), but the tag store correctly records
      // "not a real capability" for those bytes.
      let _ = write_ram(Write_plain, paddr, 32, packed, store_tag);
      RETIRE_SUCCESS
    },
  }
}

mapping clause assembly = VEDA_OCL_C(rs2, rs1, rd)
  <-> "ocl.c" ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)

mapping clause assembly = VEDA_OCS_C(rs2, rs1, rd)
  <-> "ocs.c" ^ spc() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2) ^ sep() ^ vcap_name(encdec_vcap(rd))

// NMC_ADD (VEDA_CORE_SPEC.md Section 1), Milestone V-B. R-type, Custom-0,
// funct7 = 0000010. Unlike OCL/OCS, NMC_ADD uses the capability's own
// persistent Offset field (set in advance via OCA, Custom-2) rather than a
// fresh rs2-held offset -- rs2 is already committed to the add's value
// operand, matching the spec's own stated reason OCA exists.
//
// Semantics adapted directly from the real, local AMOADD implementation
// (extensions/A/zaamo_insts.sail, read in full before writing this): rs2
// is truncated to the operation's width (not sign-extended) before the
// add; the add itself wraps within that width; rd receives the
// sign-extended *old* (pre-add) value, matching AMOADD's own return
// convention exactly, per VEDA_CORE_SPEC.md Section 1's explicit text.
//
// Two concrete instructions (W/D), not a single width-polymorphic one --
// matches this codebase's own existing convention (OCL/OCS are concrete
// per-width instructions, not polymorphic), not a new idiom.

// NMC_ADD's own dedicated permission (Permit_NMC_Compute, Section 2) --
// distinct from OCL/OCS's Permit_Load/Permit_Store, since this is a
// compute-at-memory dispatch, not a data movement operation (Section 3's
// own dedicated cause code, 0x1f, for exactly this permission).
function veda_check_nmc_access(capidx : vcapno, width : int) -> result(physaddr, ExecutionResult) = {
  let cap = C(capidx);
  let entry = odt_lookup(cap.Object_ID);
  // Offset is 40 bits now -- widen through the explicit 64-bit domain.
  let offset : xlenbits = veda_to_xlen(zero_extend(cap.Offset));
  if not(CTag(capidx)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if not(entry.valid) | entry.generation != cap.generation then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if isSealedCap(cap) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_SEAL_VIOLATION))
  else if not(permBit(cap.Perms, PERM_NMC_COMPUTE)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_NMC_COMPUTE_VIOLATION))
  // NMC_ADD IS A LOAD AND A STORE, and until now it asked for neither.
  //
  // The clause below this one calls read_ram, returns the loaded value in rd,
  // and calls write_ram. Permit_NMC_Compute was the ONLY permission gate, so a
  // capability with Permit_Store deliberately stripped could still write
  // through NMC_ADD -- and the seeded fixture's Perms 0x100C carries
  // Load|Store|NMC_Compute together, so an attenuated capability keeps bit 12
  // and the write lands. That makes every store-side attenuation in the
  // architecture advisory, including the one DESIGN_02's copy-on-write is
  // specified to be built on.
  //
  // Veda-Atomic already settled this for the identical instruction shape:
  // veda_atomic_insts.sail:34 says in as many words "Permission: reuses
  // Permit_Load + Permit_Store", and its checker call passes (true, true).
  // Two read-modify-write families in one model answered the same question
  // two different ways; this is the one that was never asked.
  //
  // Permit_NMC_Compute stays, as an ADDITIONAL gate ("this object may be
  // computed on near memory"), not as a substitute. The principle: a value
  // reaching software from memory is a load and a value reaching memory is a
  // store, whatever single instruction performs them.
  else if not(permBit(cap.Perms, PERM_LOAD)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_LOAD_VIOLATION))
  // NMC_ADD writes memory, so copy-on-write must catch it here too. R15 found
  // this same path missing the store permission entirely, one increment ago;
  // the question that finds it is "where is memory WRITTEN", never "where is
  // the cow bit already read".
  // R19 increment 1 -- gated exactly as veda_check_access's arm is, and for the
  // same reason. NOTE these two arms are deliberately NOT textually identical
  // to that function's: NMC_ADD is unconditionally read-modify-write, so there
  // is no need_store conjunct here. The two checkers are otherwise kept
  // textually parallel on purpose so they stay diffable -- this one arm is the
  // exception, and it is an exception by design, not a transcription error.
  else if not(permBit(cap.Perms, PERM_STORE)) & not(entry.cow) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_STORE_VIOLATION))
  else if unsigned(offset) + width > unsigned(cap.Length) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_BOUNDS_VIOLATION))
  // DESIGN_02 -- OBJECT residency, checked HERE and not only at Bind. This
  // term closes a real hole, and it is free: `entry` is already read above,
  // so it costs no additional ODT access. (Both dereference checkers carry
  // this identically -- keep them textually parallel so they stay diffable.)
  //
  // Why bind-only would be unsound. The address below is computed from
  // `cap.Base` -- the capability's CACHED copy -- never from entry.Base. A
  // page-out that frees this object's frame and reassigns it elsewhere is
  // therefore invisible to this path: `valid` stays true (the object still
  // exists), and `generation` is bumped only by Populate and Destroy, never
  // by paging. So a capability minted while the object was resident and
  // held across a page-out would read and write whatever now occupies that
  // memory. The codebase already records that held-across-page-out state as
  // legal and reachable for regions; for objects it is worse, because it is
  // the contents themselves that moved.
  //
  // The DESIGN_08 region precedent deliberately does NOT transfer. Region
  // residency governs whether a domain's TABLE is paged in -- and by the
  // time control reaches here the capability has already cached everything
  // it needs from that table, so the table's absence changes nothing about
  // this access. Object residency governs the BACKING MEMORY the cached
  // Base points at. Same word, different referent, opposite conclusion.
  //
  // Placed LAST among the entry-derived checks, matching the rule OCInvoke's
  // region gate already established: a capability that is untagged, stale,
  // sealed, unpermitted or out of bounds still reports its own real cause,
  // and RESIDENCY_FAULT is raised only for an access that would otherwise
  // have SUCCEEDED. That is exactly what a resumable pager fault should
  // mean -- page the object in, re-execute, proceed.
  else if not(entry.resident) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_RESIDENCY_FAULT))
  // R19 increment 1 -- cow moved LAST here too; see veda_check_access for the
  // full reasoning. Bare, with no need_store conjunct, because NMC_ADD always
  // writes.
  else if entry.cow then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_COW_FAULT))
  else {
    // Phase 1 increment 2: Base is now 56 bits, so zero-extending it
    // straight into xlenbits is ill-typed whenever xlen could be 32. The
    // sum is computed in an explicit 64-bit domain and narrowed once via
    // veda_to_xlen (DESIGN_01 decision 7: Ext_Veda is RV64-only, and the
    // encdec's own xlen==64 guard is deliberately not visible to the type
    // checker inside an execute body -- a lesson already recorded in this
    // file for VEDA_NMC_ADD_D).
    let real_loc64 : bits(64) = zero_extend(cap.Base) + zero_extend(offset);
    let real_loc : xlenbits = veda_to_xlen(real_loc64);
    Ok(Physaddr(zero_extend(real_loc)))
  }
}

union clause instruction = VEDA_NMC_ADD_W : (regidx, vcapidx, regidx)
union clause instruction = VEDA_NMC_ADD_D : (regidx, vcapidx, regidx)

// funct3 = 010 (W) / 011 (D), VEDA_CORE_SPEC.md Section 1's NMC_ADD width
// table (deliberately not OCL/OCS's full B/H/W/D/C table -- mirrors real
// RISC-V Zaamo's own W/D-only restriction; RISC-V defines no byte- or
// halfword-width atomics at all). W is legal at any xlen (matches real
// AMOADD.W, itself legal on both RV32 and RV64); D needs xlen==64,
// mirroring OCL.D/OCS.D's own existing convention in this file.
mapping clause encdec = VEDA_NMC_ADD_W(rs2, rs1, rd)
  <-> 0b0000010 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b010 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda)

mapping clause encdec = VEDA_NMC_ADD_D(rs2, rs1, rd)
  <-> 0b0000010 @ encdec_reg(rs2) @ 0b0 @ encdec_vcap(rs1) @ 0b011 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

function clause execute VEDA_NMC_ADD_W(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  match veda_check_nmc_access(capidx, 4) {
    Err(res) => res,
    Ok(paddr) => {
      let (loaded, _) : (bits(32), mem_meta) = read_ram(Read_plain, paddr, 4, false);
      let rs2_val : bits(32) = X(rs2)[31..0];
      let result : bits(32) = rs2_val + loaded;
      let _ = write_ram(Write_plain, paddr, 4, result, default_meta);
      X(rd) = sign_extend(loaded);
      RETIRE_SUCCESS
    },
  }
}

function clause execute VEDA_NMC_ADD_D(rs2, rs1, rd) = {
  // xlenbits/xlen_bytes, not hardcoded bits(64)/8 -- the encdec `when`
  // clause's xlen==64 constraint isn't visible to the type-checker inside
  // this execute body (a real type error, not assumed), same lesson
  // already learned and recorded for OCL.D/OCS.D above.
  let capidx = vcapidx_to_vcapno(rs1);
  match veda_check_nmc_access(capidx, xlen_bytes) {
    Err(res) => res,
    Ok(paddr) => {
      let (loaded, _) : (xlenbits, mem_meta) = read_ram(Read_plain, paddr, xlen_bytes, false);
      let rs2_val : xlenbits = X(rs2);
      let result : xlenbits = rs2_val + loaded;
      let _ = write_ram(Write_plain, paddr, xlen_bytes, result, default_meta);
      X(rd) = sign_extend(loaded);
      RETIRE_SUCCESS
    },
  }
}

mapping clause assembly = VEDA_NMC_ADD_W(rs2, rs1, rd)
  <-> "nmc_add.w" ^ spc() ^ reg_name(rd) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)

mapping clause assembly = VEDA_NMC_ADD_D(rs2, rs1, rd)
  <-> "nmc_add.d" ^ spc() ^ reg_name(rd) ^ sep() ^ vcap_name(encdec_vcap(rs1)) ^ sep() ^ reg_name(rs2)

// ODT-Populate / ODT-Destroy (VEDA_CORE_SPEC.md Section 5.1), Milestone
// V-B: replaces the temporary veda_test_seed_odt() scaffold with a real
// instruction. R-type, Custom-0, funct7 = 0000011, funct3 selects
// Populate (000) vs Destroy (001) under that one funct7 -- the design
// decision and its full reasoning (including the honest deviation from
// "gated by Permit_Access_System_Registers" to ordinary M-mode-only
// privilege, forced by the R-type operand budget having no room left for
// a capability-authority operand) is written up in the spec, not just
// here. Unlike every other Custom-0 instruction, rs1 here is an ordinary
// GPR holding Object_ID (mirroring Object-Bind's own rs1 convention
// exactly), not a capability register -- so it uses encdec_reg, not
// encdec_vcap.
union clause instruction = VEDA_ODT_POPULATE : (regidx, regidx, regidx)
union clause instruction = VEDA_ODT_DESTROY  : (regidx, regidx)

mapping clause encdec = VEDA_ODT_POPULATE(rs2, rs1, rd)
  <-> 0b0000011 @ encdec_reg(rs2) @ encdec_reg(rs1) @ 0b000 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

mapping clause encdec = VEDA_ODT_DESTROY(rs1, rd)
  <-> 0b0000011 @ 0b00000 @ encdec_reg(rs1) @ 0b001 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda)

// `bits(64)` via zero_extend, not a direct xlenbits->bits(64) ascription
// -- the latter needs Sail to statically prove xlen==64 (the same class
// of error already hit and fixed for OCL/OCS/NMC_ADD.D above), which
// zero_extend sidesteps by widening rather than asserting equality. Safe
// in practice because the encdec `when` clause already makes this
// execute body unreachable at xlen==32.
// Milestone 11 (NEXT_STEPS_ROADMAP.md §2.5, "capability-authority-gated
// ODT-Populate/ODT-Destroy"): the real capability-authority path this
// project's own spec named and deferred since Milestone 4 ("a real
// capability-permission-gated version would need Veda-Core's own
// privileged-capability model designed first"). Now that the ODA
// (Object Descriptor Authority, veda_regs.sail) exists, ordinary
// privilege is no longer the ONLY path -- a live, unsealed capability
// delegated into the ODA (via OSpecialRW) and carrying
// PERMIT_ACCESS_SYSTEM_REGISTERS (the same real CHERI permission bit
// that gates its own SCR access, VEDA_CORE_SPEC.md Section 2, activated
// but never before consumed by any instruction) is a second, real,
// independent authorization -- an OR, not a replacement: ordinary
// M-mode privilege still always suffices on its own, exactly matching
// CHERI's own layered model (Section 3.11.1's own real "ring-based
// privilege" and "capability control of ring-related privilege"
// coexisting, verified directly from source, not assumed) rather than
// one replacing the other.
function veda_oda_authorized() -> bool =
  veda_oda_tag & not(isSealedCap(veda_oda)) & permBit(veda_oda.Perms, PERM_ACCESS_SYSTEM_REGISTERS)

function clause execute VEDA_ODT_POPULATE(rs2, rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    // Sliced out of an explicit 64-bit widening: a direct X(..)[43..0]
    // is not provably in range when xlen might be 32 (Ext_Veda is
    // RV64-only, but that gate is invisible to the type checker here).
    let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
    let object_id : bits(44) = object_id_gpr64[43..0];
    // R11(b) (DESIGN_07 Tier H): POPULATE IS AN EVICTION PATH TOO, and it
    // is the one that made the refusal BYPASSABLE rather than partial.
    // Repopulating a still-VALID slot bumps the generation (killing every
    // outstanding capability) AND repoints Base/Length/Perms -- everything
    // Destroy does, and more. An authority refused a Destroy on the running
    // compartment's code object could simply re-populate it instead, and
    // PCC would keep executing the cached old Base while the object it
    // names now backs something else entirely.
    //
    // Found by reading the RTL for an unrelated reason, which is a bad way
    // to find a bypass. The complete consumer set of this predicate is
    // answerable exactly -- every instruction that can change an entry's
    // identity or backing -- and it is Populate, Populate-Fast, Destroy and
    // page-out. Page-in is deliberately NOT in it: it already refuses
    // unless the object is non-resident, and an executing object is
    // necessarily resident.
    if veda_object_is_executing(object_id) then Illegal_Instruction()
    else {
    let descriptor : bits(64) = zero_extend(X(rs2));
    let old_entry = odt_lookup(object_id);
    // RTL Milestone 16 mirror (veda_types.sail's own `retired` field
    // comment has the full real reasoning): a slot that has already
    // exhausted its real generation counter can never be safely
    // repopulated again -- a stale capability cached from any point
    // after saturation would be permanently indistinguishable from a
    // genuinely new object otherwise. Illegal_Instruction() matches
    // this same instruction's own existing convention for its other
    // real failure mode (privilege), just above.
    if old_entry.retired then Illegal_Instruction()
    else {
      // A slot being repopulated while still `valid` bumps generation too
      // (not just Destroy) -- the ODT's own real security property (a
      // stale capability's cached generation must stop matching once its
      // Object_ID means something else) has to hold regardless of whether
      // software destroyed the old entry first or overwrote it directly.
      // RTL Milestone 16: once already at 0xff, freeze instead of
      // wrapping back to 0 -- `new_retired` (below) is what actually
      // stops the slot from ever being reused once this point is
      // reached.
      let new_generation : bits(24) =
        if old_entry.valid then (if old_entry.generation == 0xffffff then 0xffffff else old_entry.generation + 1)
        else old_entry.generation;
      let new_retired : bool = old_entry.valid & (old_entry.generation == 0xffffff);
      odt_write(object_id, struct {
        valid      = true,
        // Increment 3: plain Populate keeps its packed single-GPR
        // descriptor and is now explicitly the COMPACT form -- Base 32 /
        // Length 16, zero-extended into the wide entry. 112 bits of
        // Base(56)+Length(40)+Perms(16) simply cannot fit one GPR, so
        // rather than inventing a multi-operand encoding here, the compact
        // form is kept for the ordinary small-object case (and every
        // existing program keeps working unchanged) while
        // ODT-Populate-Fast below carries the full width. The limit is in
        // the ENCODING, visibly, not a silent truncation of a wide value.
        Base       = zero_extend(descriptor[63..32]),
        Length     = zero_extend(descriptor[31..16]),
        Perms      = descriptor[15..0],
        generation = new_generation,
        // Milestone 12 (in progress): a (re)populated slot always resets
        // to unowned -- ownership is claimed by the first real Bind, not
        // granted at populate time. This field is not yet consumed by any
        // check (Bind/Rebind enforcement is the next real step of this
        // milestone) -- stated here rather than left silently undone.
        owner_hart = VEDA_OWNER_UNOWNED,
        retired    = new_retired,
        // DESIGN_02: a populate ESTABLISHES residency. Explicit `true`, not
        // a carry-over: Populate/Populate-Fast is exactly how the residency
        // handler repairs a fault -- DESIGN_02's own flow is "fetches
        // contents from backing, allocates physical Base (ODT-Populate
        // -Fast), sets resident, and resumes". It supplies a fresh Base, so
        // by construction the contents it names are present. Carrying the
        // old value over would leave a just-populated object faulting
        // forever, which is why this is spelled out rather than inherited.
        resident   = true,
        owner_domain = old_entry.owner_domain,
        cow = old_entry.cow,
      });
      X(rd) = zeros();
      RETIRE_SUCCESS
    }
  }
  }
}

function clause execute VEDA_ODT_DESTROY(rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    // Sliced out of an explicit 64-bit widening: a direct X(..)[43..0]
    // is not provably in range when xlen might be 32 (Ext_Veda is
    // RV64-only, but that gate is invisible to the type checker here).
    let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
    let object_id : bits(44) = object_id_gpr64[43..0];
    // R11(b): you may not destroy the code you are running, nor the code a
    // pending return still owes. Without this, Destroy revokes every DATA
    // view of an object while the PCC keeps executing it from cached bounds
    // -- execute-after-free, the half R11(a) structurally could not reach.
    //
    // THE HONEST COST. On this hart revocation is never actually blocked: a
    // trap resets PCC to no-object, so a handler can always abandon the
    // frame and then destroy. What that forces is a DELIBERATE act -- "I am
    // not returning to this compartment" -- stated before the object dies,
    // rather than the object dying under a compartment that still expects to
    // resume. On ANOTHER hart the refusal is real: an object being executed
    // elsewhere cannot be destroyed until that hart is stopped. That is the
    // same bargain a conventional machine strikes when it cannot unmap a
    // page another core is running from without interrupting it, and it is
    // preferred here over the alternative, which is letting the other hart
    // keep executing freed memory.
    if veda_object_is_executing(object_id) then Illegal_Instruction()
    else {
    let old_entry = odt_lookup(object_id);
    // RTL Milestone 16: Destroy always bumps (unlike Populate, it is not
    // itself gated by `retired` -- destroying an already-retired slot is
    // harmless, it just stays invalid and retired), but the same
    // freeze-at-0xff-and-retire rule applies once the counter is
    // exhausted.
    let new_generation : bits(24) = if old_entry.generation == 0xffffff then 0xffffff else old_entry.generation + 1;
    let new_retired : bool = old_entry.retired | (old_entry.generation == 0xffffff);
    odt_write(object_id, struct {
      valid      = false,
      Base       = old_entry.Base,
      Length     = old_entry.Length,
      Perms      = old_entry.Perms,
      generation = new_generation,
      owner_hart = VEDA_OWNER_UNOWNED,
      retired    = new_retired,
      // DESIGN_02: a destroyed object has no physical backing, so it is not
      // resident. Deliberately NOT observable as a residency fault, and that
      // is correct: `valid = false` above already traps first at the
      // dereference re-check, so a destroyed object keeps reporting the
      // stale-capability cause rather than inviting a pager to resurrect
      // something that was deliberately revoked. Set for state hygiene, so
      // no path can ever read a stale `resident = true` off a dead slot.
      resident   = false,
      owner_domain = VEDA_DOMAIN_ANY,
      cow = false,
    });
    X(rd) = zeros();
    RETIRE_SUCCESS
    }
  }
}

mapping clause assembly = VEDA_ODT_POPULATE(rs2, rs1, rd)
  <-> "veda.odt.populate" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = VEDA_ODT_DESTROY(rs1, rd)
  <-> "veda.odt.destroy" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)

// Milestone 18 (IMMEDIATE_LIMIT_INVESTIGATION): a second Populate encoding
// that avoids the 64-bit packed-descriptor `li` entirely. Real, measured
// motivation: RV64I's 12-bit immediate forces a full 6-instruction `li`
// per object under plain VEDA_ODT_POPULATE above, and a real, dedicated
// benchmark showed a software-only `la`-based workaround saves only ~5%
// (Base still has to be shifted into the descriptor's upper 32 bits
// regardless of how it's loaded). Here `rs2` is Base directly (loadable
// via a clean, real 2-instruction `la`, no shifting/packing needed) and
// Length/Perms come from `veda_attr` (veda_regs.sail, CSR 0x7C4) --
// intended for the real, common case of multiple objects sharing one
// size/permission template, the same real pattern the IMMEDIATE_LIMIT
// benchmark's "optimized" program already used in software. Same
// Custom-0 major opcode, funct3 = 000 (grouping with the Populate
// family), funct7 = 0000100 -- the next genuinely free slot, verified by
// grepping every existing $is_veda_* decode condition in veda_core.tlv
// before choosing it (Custom-0's existing allocations: OCL 011/0000000,
// OCS 011/0000001, OCL.C 100/0000000, OCS.C 100/0000001, ODT-Populate
// 000/0000011, ODT-Destroy 001/0000011, NMC_ADD.W 010/0000010,
// NMC_ADD.D 011/0000010, Bind 101/any).
union clause instruction = VEDA_ODT_POPULATE_FAST : (regidx, regidx, regidx)

mapping clause encdec = VEDA_ODT_POPULATE_FAST(rs2, rs1, rd)
  <-> 0b0000100 @ encdec_reg(rs2) @ encdec_reg(rs1) @ 0b000 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

// Identical privilege/retired/generation-counter logic to VEDA_ODT_POPULATE
// above (deliberately mirrored, not refactored into a shared helper --
// this codebase's own established style keeps each instruction's execute
// clause self-contained and independently readable/auditable, matching
// how VEDA_ODT_DESTROY above already duplicates rather than shares logic
// with VEDA_ODT_POPULATE). The only real difference: Base = X(rs2)
// directly (no packed-descriptor unpacking), Length/Perms = veda_attr.
function clause execute VEDA_ODT_POPULATE_FAST(rs2, rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    // Sliced out of an explicit 64-bit widening: a direct X(..)[43..0]
    // is not provably in range when xlen might be 32 (Ext_Veda is
    // RV64-only, but that gate is invisible to the type checker here).
    let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
    let object_id : bits(44) = object_id_gpr64[43..0];
    // R11(b) (DESIGN_07 Tier H): POPULATE IS AN EVICTION PATH TOO, and it
    // is the one that made the refusal BYPASSABLE rather than partial.
    // Repopulating a still-VALID slot bumps the generation (killing every
    // outstanding capability) AND repoints Base/Length/Perms -- everything
    // Destroy does, and more. An authority refused a Destroy on the running
    // compartment's code object could simply re-populate it instead, and
    // PCC would keep executing the cached old Base while the object it
    // names now backs something else entirely.
    //
    // Found by reading the RTL for an unrelated reason, which is a bad way
    // to find a bypass. The complete consumer set of this predicate is
    // answerable exactly -- every instruction that can change an entry's
    // identity or backing -- and it is Populate, Populate-Fast, Destroy and
    // page-out. Page-in is deliberately NOT in it: it already refuses
    // unless the object is non-resident, and an executing object is
    // necessarily resident.
    if veda_object_is_executing(object_id) then Illegal_Instruction()
    else {
    // Increment 3: Base is taken at its full 56-bit width from the GPR --
    // this is the WIDE populate path. Sliced out of an explicit 64-bit
    // widening for the usual reason (a direct xlenbits[55..0] is not
    // provably in range when xlen might be 32).
    let base_gpr64 : bits(64) = zero_extend(X(rs2));
    let base : bits(56) = base_gpr64[55..0];
    let old_entry = odt_lookup(object_id);
    if old_entry.retired then Illegal_Instruction()
    else {
      let new_generation : bits(24) =
        if old_entry.valid then (if old_entry.generation == 0xffffff then 0xffffff else old_entry.generation + 1)
        else old_entry.generation;
      let new_retired : bool = old_entry.valid & (old_entry.generation == 0xffffff);
      odt_write(object_id, struct {
        valid      = true,
        Base       = base,
        // veda_attr widened to 64 bits with Length occupying [55..16] and
        // Perms [15..0]. Keeping Length's LOW end at bit 16 and growing it
        // upward makes this change backward compatible BY CONSTRUCTION: a
        // program that wrote a 32-bit attr value still yields exactly the
        // same Length and Perms, because the extra bits it never set read
        // as zero. That is why no existing fast-populate program needed
        // touching.
        Length     = veda_attr[55..16],
        Perms      = veda_attr[15..0],
        generation = new_generation,
        owner_hart = VEDA_OWNER_UNOWNED,
        retired    = new_retired,
        // DESIGN_02: a populate ESTABLISHES residency. Explicit `true`, not
        // a carry-over: Populate/Populate-Fast is exactly how the residency
        // handler repairs a fault -- DESIGN_02's own flow is "fetches
        // contents from backing, allocates physical Base (ODT-Populate
        // -Fast), sets resident, and resumes". It supplies a fresh Base, so
        // by construction the contents it names are present. Carrying the
        // old value over would leave a just-populated object faulting
        // forever, which is why this is spelled out rather than inherited.
        resident   = true,
        owner_domain = VEDA_DOMAIN_ANY,
        cow = false,
      });
      X(rd) = zeros();
      RETIRE_SUCCESS
    }
  }
  }
}

mapping clause assembly = VEDA_ODT_POPULATE_FAST(rs2, rs1, rd)
  <-> "veda.odt.populate.fast" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

// ─────────────────────────────────────────────────────────────────────────
//  DESIGN_02 Phase 2, increment 2 -- the PAGE-OUT / PAGE-IN pair.
//
//  These two implement the cached-Base contract decided in DESIGN_02 ("The
//  cached-Base fork"): a capability caches Base at Bind time, and paging
//  necessarily returns an object at a DIFFERENT Base, so the cached copy
//  must be invalidated. The chosen resolution bumps `generation` on
//  PAGE-OUT -- holders then take the existing stale-capability trap (0x02),
//  re-Bind, and receive the new Base -- rather than removing Base caching,
//  which would have added a DRAM read to every access and damaged both the
//  cache-less and determinism pillars for a rare event.
//
//  Encodings share funct7 0b0000101 and split on funct3 by operand shape,
//  exactly as ODT-Populate (000) and ODT-Destroy (001) already share
//  0b0000011: PAGE-IN is three-operand (rs2 = new Base), PAGE-OUT is
//  two-operand (rs2 hardwired zero). Both points verified unallocated in
//  this model AND in the RTL's own decode before use.
//
//  WHY THIS GRANTS NO NEW AUTHORITY, which is the first thing to check for
//  a primitive that writes Base: PAGE-OUT followed by PAGE-IN is
//  observationally equal to one ODT-Populate-Fast (net generation +1,
//  arbitrary new Base, resident). The pager already holds exactly that
//  power under the same gate. The two field-level differences both TIGHTEN
//  it: Populate resets owner_hart to unowned and lets veda_attr
//  re-permission the object, whereas PAGE-IN preserves owner_hart, Length
//  and Perms. Paging an object may move it; it may not re-authorize it.
// ─────────────────────────────────────────────────────────────────────────

// ═══ veda.odt.set.domain -- THE POLICY WRITE PATH ═══
//
// The first instruction in this design that changes an ODT entry WITHOUT
// changing what the object is. Every other writer -- Populate, Populate-Fast,
// Destroy -- bumps the generation, which kills every outstanding capability.
// That is right for them: they change Base, Length or existence, so the object
// really has become a different object.
//
// Policy is not identity. Narrowing who may bind an object must NOT invalidate
// the capabilities already held by those still entitled to it -- otherwise
// declaring a sharing rule destroys the sharing it describes. DESIGN_02 records
// exactly this gap: there is no way to set a per-object policy bit without
// collateral damage, which is why both copy-on-write and per-object bind
// authority have been blocked on it.
//
// DELIBERATELY NARROW. This is not a general "write any ODT field" instruction,
// and it must never become one. Base, Length, generation, valid and retired stay
// unreachable from here: those say WHAT the object is, and letting software edit
// them would turn the ODT into an ordinary table with a security story bolted on.
// The line is: identity changes cost a generation bump, policy changes do not.
// veda.odt.set.cow -- the second POLICY field, same contract as the first:
// it writes one field and does not bump the generation.
//
// A SEPARATE INSTRUCTION rather than a field selector on set.domain, and that
// is a hardware-first choice. A selector would let SOFTWARE name which field to
// write, so the set of writable fields would live in a register; separate
// instructions keep it fixed in the decoder, where software cannot reach it.
// The funct7 space in this family is nearly empty, so there is no encoding
// pressure pushing the other way.
union clause instruction = VEDA_ODT_SET_COW : (regidx, regidx, regidx)

mapping clause encdec = VEDA_ODT_SET_COW(rs2, rs1, rd)
  <-> 0b0000111 @ encdec_reg(rs2) @ encdec_reg(rs1) @ 0b001 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

function clause execute VEDA_ODT_SET_COW(rs2, rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
    let object_id : bits(44) = object_id_gpr64[43..0];
    let flag_gpr64 : bits(64) = zero_extend(X(rs2));
    let new_cow : bool = flag_gpr64[0] == bitone;
    let old_entry = odt_lookup(object_id);
    if not(old_entry.valid) then Illegal_Instruction()
    else {
      odt_write(object_id, struct {
        valid      = old_entry.valid,
        Base       = old_entry.Base,
        Length     = old_entry.Length,
        Perms      = old_entry.Perms,
        // NOT bumped. fork() marks the parent's objects copy-on-write while
        // both parent and child hold live capabilities to them; bumping here
        // would kill exactly those, at exactly the moment they are needed.
        generation = old_entry.generation,
        owner_hart = old_entry.owner_hart,
        retired    = old_entry.retired,
        resident   = old_entry.resident,
        owner_domain = old_entry.owner_domain,
        cow        = new_cow,
      });
      X(rd) = zeros();
      RETIRE_SUCCESS
    }
  }
}

mapping clause assembly = VEDA_ODT_SET_COW(rs2, rs1, rd)
  <-> "veda.odt.set.cow" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

union clause instruction = VEDA_ODT_SET_DOMAIN : (regidx, regidx, regidx)

mapping clause encdec = VEDA_ODT_SET_DOMAIN(rs2, rs1, rd)
  <-> 0b0000110 @ encdec_reg(rs2) @ encdec_reg(rs1) @ 0b001 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

function clause execute VEDA_ODT_SET_DOMAIN(rs2, rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
    let object_id : bits(44) = object_id_gpr64[43..0];
    let domain_gpr64 : bits(64) = zero_extend(X(rs2));
    let new_domain : bits(20) = domain_gpr64[19..0];
    let old_entry = odt_lookup(object_id);
    // Refuse on a slot that holds nothing: a policy on a non-existent object is
    // meaningless, and allowing it would let software pre-stage rules on slots
    // it does not own yet, to take effect when someone else populates them.
    if not(old_entry.valid) then Illegal_Instruction()
    else {
      odt_write(object_id, struct {
        // EVERYTHING except owner_domain is copied verbatim. In particular the
        // generation is NOT bumped -- that is the entire purpose of this
        // instruction, and the one line that must never be "tidied up".
        valid      = old_entry.valid,
        Base       = old_entry.Base,
        Length     = old_entry.Length,
        Perms      = old_entry.Perms,
        generation = old_entry.generation,
        owner_hart = old_entry.owner_hart,
        retired    = old_entry.retired,
        resident   = old_entry.resident,
        owner_domain = new_domain,
        cow = old_entry.cow,
      });
      X(rd) = zeros();
      RETIRE_SUCCESS
    }
  }
}

mapping clause assembly = VEDA_ODT_SET_DOMAIN(rs2, rs1, rd)
  <-> "veda.odt.set.domain" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

union clause instruction = VEDA_ODT_PAGE_OUT : (regidx, regidx)

mapping clause encdec = VEDA_ODT_PAGE_OUT(rs1, rd)
  <-> 0b0000101 @ 0b00000 @ encdec_reg(rs1) @ 0b001 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

// PAGE-OUT: the object's contents leave memory and its frame is freed.
// Sets resident = false and BUMPS generation, which is what invalidates
// every outstanding capability. Everything else carries over -- this is
// not a destroy: the object still EXISTS, which is exactly the distinction
// increment 1's RESIDENCY_FAULT (0x0A) exists to express.
//
// THE SATURATION REFUSAL, and it is the security core of this increment.
// The whole safety argument for the bump-on-page-out contract is that the
// bump invalidates outstanding capabilities. `generation` SATURATES at
// 0xffffff rather than wrapping (the existing rule in Populate and Destroy
// above). So at saturation the bump would be a silent NO-OP: page-out
// would clear residency while invalidating nothing, and the subsequent
// PAGE-IN -- which preserves generation by design -- would restore
// residency at a NEW Base while every outstanding capability still matched
// on generation. Those capabilities compute their address from their own
// CACHED Base, so each would read and write the freed frame, now owned by
// another object. That is a full use-after-free, and it is the precise
// attack this pair is built to prevent, reappearing at the boundary.
//
// That state is genuinely reachable, not theoretical: a Destroy from
// 0xfffffe leaves generation 0xffffff with retired STILL false (its
// retired rule tests the OLD generation), and a following Populate is then
// permitted and leaves the slot valid, resident, saturated and un-retired.
// So `retired` does not intercept it.
//
// Fix, placed here rather than on PAGE-IN because this is the instruction
// making the promise: if the invalidation mechanism cannot run, the
// operation that depends on it must not proceed. FAIL CLOSED. Refusing
// costs a pager the ability to evict one exhausted object; permitting it
// costs the temporal-safety guarantee of the whole design.
function clause execute VEDA_ODT_PAGE_OUT(rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
    let object_id : bits(44) = object_id_gpr64[43..0];
    let old_entry = odt_lookup(object_id);
    // Only a live, resident object can be paged out. A non-existent one has
    // nothing to evict; an already-paged-out one would bump generation a
    // second time for no benefit, burning the budget and invalidating the
    // capabilities a pending page-in was about to serve.
    // R11(b): refuse to evict the object backing the running compartment or
    // the one a pending return owes. Placed FIRST deliberately -- an
    // executing object is refused whether or not it is otherwise evictable,
    // so no future relaxation of the residency gates below can open this.
    if veda_object_is_executing(object_id) then Illegal_Instruction()
    else if not(old_entry.valid) | not(old_entry.resident) then Illegal_Instruction()
    // The saturation refusal described above.
    else if old_entry.generation == 0xffffff then Illegal_Instruction()
    else {
      odt_write(object_id, struct {
        valid      = true,          // the object still EXISTS
        Base       = old_entry.Base, // stale, and unreachable: increment 1's
                                     // Bind residency gate traps before any
                                     // mode can mint from it
        Length     = old_entry.Length,
        Perms      = old_entry.Perms,
        // The bump. Guarded above, so this can never be the saturating
        // no-op -- it always genuinely invalidates.
        generation = old_entry.generation + 1,
        owner_hart = old_entry.owner_hart,
        retired    = old_entry.retired,
        resident   = false,
        owner_domain = old_entry.owner_domain,
        cow = old_entry.cow,
      });
      X(rd) = zeros();
      RETIRE_SUCCESS
    }
  }
}

mapping clause assembly = VEDA_ODT_PAGE_OUT(rs1, rd)
  <-> "veda.odt.page.out" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)

union clause instruction = VEDA_ODT_PAGE_IN : (regidx, regidx, regidx)

mapping clause encdec = VEDA_ODT_PAGE_IN(rs2, rs1, rd)
  <-> 0b0000101 @ encdec_reg(rs2) @ encdec_reg(rs1) @ 0b000 @ encdec_reg(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda) & xlen == 64

// PAGE-IN: the object's contents are back in memory, at a NEW frame.
// Changes EXACTLY TWO fields -- Base and resident. Length, Perms,
// owner_hart, retired, generation and valid all carry over, because this
// is the same object moving, not a repopulate. Writing it in the
// name-every-field shape (the `claimed_entry` idiom) is deliberate: Sail
// has no record-update shorthand here, so every field is a decision the
// compiler forces rather than a default that slips through.
//
// THE GATE: valid & NOT resident. Its meaning -- "you may only page IN
// something a page-OUT produced" -- is true BY CONSTRUCTION, not by
// convention. Enumerating every odt_write in the model shows why: Populate
// and Populate-Fast always write resident = true; Destroy writes valid =
// false together with resident = false; the Bind/Rebind claim carries
// residency over unchanged AND is preceded by increment 1's residency gate,
// which traps before the write is reached. So PAGE-OUT is the sole producer
// of {valid, not resident}, and this instruction therefore cannot be aimed
// at a live object or a destroyed one.
//
// That is what makes a generation-PRESERVING Base write safe. Between
// page-out and page-in, no capability carrying the current generation can
// exist: capabilities take their generation only from a Bind, and Bind
// hard-traps on exactly this state for all three of its modes. The new Base
// becomes reachable only through a fresh Bind afterwards.
//
// HONEST LIMITATION, recorded rather than hidden: the reset test scaffold
// seeds one object into {valid, not resident} WITHOUT a generation bump
// (the increment-1 residency fixture, paired with a live capability that
// still matches its generation). That state is a test artifact, not one a
// real machine can produce -- but paging THAT object in would revalidate
// that capability at a new Base. No test may do it, and a seeded
// non-resident object is not a legitimate page-in input.
function clause execute VEDA_ODT_PAGE_IN(rs2, rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
    let object_id : bits(44) = object_id_gpr64[43..0];
    let base_gpr64 : bits(64) = zero_extend(X(rs2));
    let base : bits(56) = base_gpr64[55..0];
    let old_entry = odt_lookup(object_id);
    if not(old_entry.valid) | old_entry.resident then Illegal_Instruction()
    else {
      odt_write(object_id, struct {
        valid      = true,
        Base       = base,              // CHANGED: the new frame
        Length     = old_entry.Length,
        Perms      = old_entry.Perms,
        // PRESERVED, and this is the whole point of a separate instruction.
        // Plain Populate would bump here (its rule bumps whenever the old
        // entry was valid, and a paged-out object is valid), invalidating
        // every capability on every page-in and making demand paging
        // useless.
        generation = old_entry.generation,
        // PRESERVED. Populate hardcodes unowned, so using it as page-in
        // would silently drop hart ownership across every paging cycle --
        // invisible today with one hart, a real hole under multi-hart.
        owner_hart = old_entry.owner_hart,
        retired    = old_entry.retired,
        resident   = true,              // CHANGED: contents are back
        owner_domain = old_entry.owner_domain,
        cow = old_entry.cow,
      });
      X(rd) = zeros();
      RETIRE_SUCCESS
    }
  }
}

mapping clause assembly = VEDA_ODT_PAGE_IN(rs2, rs1, rd)
  <-> "veda.odt.page.in" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)
