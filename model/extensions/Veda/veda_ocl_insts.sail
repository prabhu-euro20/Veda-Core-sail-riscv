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
function veda_check_access(capidx : vcapno, offset : xlenbits, width : int, need_load : bool, need_store : bool) -> result(physaddr, ExecutionResult) = {
  let cap = C(capidx);
  let entry = odt_lookup(cap.Object_ID);
  if not(CTag(capidx)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if not(entry.valid) | entry.generation != cap.Reserved then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if isSealedCap(cap) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_SEAL_VIOLATION))
  else if need_load & not(permBit(cap.Perms, PERM_LOAD)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_LOAD_VIOLATION))
  else if need_store & not(permBit(cap.Perms, PERM_STORE)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_STORE_VIOLATION))
  else if unsigned(offset) + width > unsigned(cap.Length) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_BOUNDS_VIOLATION))
  else {
    let real_loc : xlenbits = zero_extend(cap.Base) + offset;
    Ok(Physaddr(zero_extend(real_loc)))
  }
}

function clause execute VEDA_OCL(rs2, rs1, rd) = {
  let capidx = vcapidx_to_vcapno(rs1);
  let offset : xlenbits = X(rs2);
  match veda_check_access(capidx, offset, xlen_bytes, true, false) {
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
  match veda_check_access(capidx, offset, xlen_bytes, false, true) {
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
  match veda_check_access(capidx, offset, 16, true, false) {
    Err(res) => res,
    Ok(paddr) => {
      // read_meta = true (unlike OCL.D/OCS.D's `false` above): this is the
      // one real access kind in this file that actually needs the
      // memory-resident Tag, not just the 128 data bits.
      let (data, tag) : (bits(128), mem_meta) = read_ram(Read_plain, paddr, 16, true);
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
  match veda_check_access(capidx, offset, 16, false, true) {
    Err(res) => res,
    Ok(paddr) => {
      let store_cap = C(rd);
      let store_tag = CTag(rd);
      let packed : bits(128) = veda_cap_pack(store_cap);
      // The store's own Tag is written to the tag store alongside the 128
      // data bits -- an untagged (CTag(rd)=false) capability register
      // still stores its raw field bits (matching CHERI's own real
      // behavior: storing an invalid capability is legal, it just can't
      // be loaded back as valid), but the tag store correctly records
      // "not a real capability" for those bytes.
      let _ = write_ram(Write_plain, paddr, 16, packed, store_tag);
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
  let offset : xlenbits = zero_extend(cap.Offset);
  if not(CTag(capidx)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if not(entry.valid) | entry.generation != cap.Reserved then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_TAG_VIOLATION))
  else if isSealedCap(cap) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_SEAL_VIOLATION))
  else if not(permBit(cap.Perms, PERM_NMC_COMPUTE)) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_PERM_NMC_COMPUTE_VIOLATION))
  else if unsigned(offset) + width > unsigned(cap.Length) then Err(veda_trap(vcapno_to_vcapidx(capidx), VEDA_CAUSE_BOUNDS_VIOLATION))
  else {
    let real_loc : xlenbits = zero_extend(cap.Base) + offset;
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
    let object_id : bits(23) = X(rs1)[22..0];
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
      let new_generation : bits(8) =
        if old_entry.valid then (if old_entry.generation == 0xff then 0xff else old_entry.generation + 1)
        else old_entry.generation;
      let new_retired : bool = old_entry.valid & (old_entry.generation == 0xff);
      odt_write(object_id, struct {
        valid      = true,
        Base       = descriptor[63..32],
        Length     = descriptor[31..16],
        Perms      = descriptor[15..0],
        generation = new_generation,
        // Milestone 12 (in progress): a (re)populated slot always resets
        // to unowned -- ownership is claimed by the first real Bind, not
        // granted at populate time. This field is not yet consumed by any
        // check (Bind/Rebind enforcement is the next real step of this
        // milestone) -- stated here rather than left silently undone.
        owner_hart = VEDA_OWNER_UNOWNED,
        retired    = new_retired,
      });
      X(rd) = zeros();
      RETIRE_SUCCESS
    }
  }
}

function clause execute VEDA_ODT_DESTROY(rs1, rd) = {
  if not(cur_privilege == Machine | veda_oda_authorized()) then Illegal_Instruction()
  else {
    let object_id : bits(23) = X(rs1)[22..0];
    let old_entry = odt_lookup(object_id);
    // RTL Milestone 16: Destroy always bumps (unlike Populate, it is not
    // itself gated by `retired` -- destroying an already-retired slot is
    // harmless, it just stays invalid and retired), but the same
    // freeze-at-0xff-and-retire rule applies once the counter is
    // exhausted.
    let new_generation : bits(8) = if old_entry.generation == 0xff then 0xff else old_entry.generation + 1;
    let new_retired : bool = old_entry.retired | (old_entry.generation == 0xff);
    odt_write(object_id, struct {
      valid      = false,
      Base       = old_entry.Base,
      Length     = old_entry.Length,
      Perms      = old_entry.Perms,
      generation = new_generation,
      owner_hart = VEDA_OWNER_UNOWNED,
      retired    = new_retired,
    });
    X(rd) = zeros();
    RETIRE_SUCCESS
  }
}

mapping clause assembly = VEDA_ODT_POPULATE(rs2, rs1, rd)
  <-> "veda.odt.populate" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = VEDA_ODT_DESTROY(rs1, rd)
  <-> "veda.odt.destroy" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
