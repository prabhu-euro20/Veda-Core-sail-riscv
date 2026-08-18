// Veda-Core formal model: Object-Bind (VEDA_CORE_SPEC.md Section 4).
//
// I-type, Custom-0 opcode (0b0001011), discriminated from the R-type OCL/OCS/
// NMC_ADD operations (veda_ocl_insts.sail) by funct3 = 0b101.

// VEDA_CORE_SPEC.md Section 3's real trap model, built on real Sail hooks
// found by reading core/types_ext.sail and core/types.sail directly, not
// assumed: ext_exc_type defaults to `unit`, and ExceptionType's
// `E_Extension : ext_exc_type` variant maps via `ext_exc_type_bits` to the
// fixed code `0b011000` (0x18 = 24) -- exactly the mcause = 24 value
// Section 3 already independently committed to. No override of
// ext_exc_type is needed: E_Extension(()) alone already gives the right
// top-level code. The `cause`/`cap_idx` sub-detail (Section 3's xtval
// layout) is carried in `excinfo`, matching how the real
// `make_sync_exception(e, xtval)` signature is built for every other
// exception in this model.
let VEDA_CAUSE_OBJECT_NOT_FOUND    : bits(5) = 0b00101 // 0x05, VEDA_CORE_SPEC.md Section 3
let VEDA_CAUSE_TAG_VIOLATION       : bits(5) = 0b00010 // 0x02
let VEDA_CAUSE_SEAL_VIOLATION      : bits(5) = 0b00011 // 0x03
let VEDA_CAUSE_BOUNDS_VIOLATION    : bits(5) = 0b00001 // 0x01
let VEDA_CAUSE_PERM_LOAD_VIOLATION  : bits(5) = 0b10010 // 0x12
let VEDA_CAUSE_PERM_STORE_VIOLATION : bits(5) = 0b10011 // 0x13
// R40 -- the two causes VEDA_CORE_SPEC.md has listed as **Active** since the
// CHERI permission adoption and that appeared ZERO times in this model and zero
// times in the RTL. Values are the specification's own, and both were verified
// free against every VEDA_CAUSE_* constant in this file before use.
//
// They govern whether AUTHORITY ITSELF may move through memory, which on an
// address-less machine is the whole of what a capability is. OCL.C/OCS.C were
// authorised by the plain data permissions alone, so a delegation made "data
// only" by clearing bit 4 could still lift a live, tagged capability out of the
// bytes it was allowed to read. Demonstrated before it was fixed, in
// sail_tests/vc_r40_cap_perm_enforce_neg.S.
let VEDA_CAUSE_PERM_LOAD_CAPABILITY_VIOLATION  : bits(5) = 0b10100 // 0x14
let VEDA_CAUSE_PERM_STORE_CAPABILITY_VIOLATION : bits(5) = 0b10101 // 0x15
// Milestone V-B addition: NMC_ADD's own dedicated permission bit
// (VEDA_CORE_SPEC.md Section 2's Perms table, Permit_NMC_Compute), not
// Permit_Load/Permit_Store -- NMC_ADD is a compute-at-memory dispatch, a
// different operation class from an ordinary load or store, and the spec
// gives it its own cause code for exactly that reason (Section 3, 0x1f).
let VEDA_CAUSE_PERM_NMC_COMPUTE_VIOLATION : bits(5) = 0b11111 // 0x1f
// OCInvoke additions (VEDA_CORE_SPEC.md's own CInvoke-equivalent design,
// Section 6 item 7 now closed): the three cause codes VEDA_CORE_SPEC.md
// Section 3 already reserved by exact value pending this design --
// 0x04/0x11/0x19 -- not freshly chosen here, just finally activated.
let VEDA_CAUSE_TYPE_VIOLATION         : bits(5) = 0b00100 // 0x04
let VEDA_CAUSE_PERM_EXECUTE_VIOLATION : bits(5) = 0b10001 // 0x11
let VEDA_CAUSE_PERM_INVOKE_VIOLATION  : bits(5) = 0b11001 // 0x19
// Milestone 12 (VEDA_CORE_SPEC.md §4.1, real, previously-named gap:
// "an owner-hart field in the ODT entry, checked at Bind/Rebind time...
// real, identified future work"): the next reserved cause slot
// (0x06-0x07 were both listed "reserved" in Section 3's own table, no
// prior instruction ever claimed either). Veda-Core-specific -- no
// CHERI equivalent, since CHERI has no concept of an object being
// "claimed" by one hart's own Object-Bind at all.
let VEDA_CAUSE_OWNER_VIOLATION : bits(5) = 0b00110 // 0x06
// Milestone 19 (Veda-Purecap Enforcement): VEDA_CORE_SPEC.md Section 3's
// own cause table lists 0x07 as "reserved" -- the next genuinely free
// value in the already-existing reservation, confirmed via a full grep of
// every VEDA_CAUSE_* constant in this file before picking it, not chosen
// arbitrarily. Fires when an ordinary (non-Veda) memory access is
// attempted either (a) while `veda_mode`'s `veda_purecap` bit is set
// (veda_regs.sail, CSR 0x7C5) -- closing the real gap where VEDA_CGETBASE
// legitimately exposes a capability's raw Base into a GPR (a real,
// spec-required query, Section 1's own "metadata is always inspectable"
// principle) but nothing previously stopped that GPR value from then
// being used as an ordinary LOAD/STORE base with zero capability check at
// all, the same real property CHERI's own "hybrid mode" has -- or (b)
// while executing inside a live OCInvoke-entered compartment
// (veda_pcc_length != VEDA_PCC_UNBOUNDED), closing a second, related gap:
// Milestone 14's PCC-bounding enforces compartment isolation for
// instruction fetch only, not ordinary data access. See
// postlude/step_ext.sail's ext_handle_data_check_error for where this
// cause is actually raised (via the same direct-construction technique
// the PCC-fetch-violation path already uses, not through veda_trap/
// vcapidx, since no real capability register is involved in either
// triggering condition).
let VEDA_CAUSE_PURECAP_VIOLATION : bits(5) = 0b00111 // 0x07
// Phase 1 increment 2 (DESIGN_01 decision 2): a capability is now 32 bytes
// and the memory tag granule widened to match, so OCL.C/OCS.C must be
// 32-byte naturally aligned -- that alignment is the ONLY rule under which
// "one capability occupies exactly one granule" is well-defined, and it is
// what keeps a plain store from tampering with half a stored capability
// while its tag survives. 0x08 is the next free cause value (verified
// against every VEDA_CAUSE_* constant in this file before picking it, the
// same discipline that once caught a real encoding collision). Hard trap,
// not soft-fail: it joins the OCL/OCS Tag/Seal violation family, and a
// misaligned capability spill is a compiler/ABI bug, not a recoverable
// condition.
let VEDA_CAUSE_CAP_MISALIGNED : bits(5) = 0b01000 // 0x08
// DESIGN_08 -- a bind whose object lives in a domain (region) whose ODT is
// not currently resident raises this bounded, EXPLICIT fault so the handler
// can page the domain's table in and retry. It is deliberately distinct from
// OBJECT_NOT_FOUND (0x05): not-found means the object never existed; a region
// fault means it exists but its table is paged out (recoverable). 0x09 is the
// next free cause value (verified against every VEDA_CAUSE_* in this file).
// The whole point of the cache-less pillar is that this is a real trap, never
// a silent miss.
let VEDA_CAUSE_REGION_FAULT : bits(5) = 0b01001 // 0x09
// DESIGN_02 (Phase 2, increment 1) -- the OBJECT-level twin of the region
// fault above, and deliberately a SEPARATE cause rather than a reuse. The
// two say different things to the handler and demand different repair:
//   0x09 REGION_FAULT    -- the domain's ODT *table* is paged out. Page the
//                           table in; the object's contents were never gone.
//   0x0A RESIDENCY_FAULT -- the object EXISTS and its table is present, but
//                           its *contents* are not in memory. Fetch them
//                           from `backing`, allocate a physical Base, set
//                           resident, retry.
// Collapsing them into one cause would send the pager after the wrong thing.
// Both are equally distinct from OBJECT_NOT_FOUND (0x05), which means the
// object never existed and is NOT recoverable.
//
// This is the cache-less pillar applied to demand paging: a miss is an
// explicit, bounded, architecturally-visible trap -- never a silent stall
// whose latency leaks which objects were resident.
//
// 0x0A verified free against every VEDA_CAUSE_* in this file before use.
// (VEDA_CORE_SPEC.md Section 3's cause table still calls 0x08-0x0f reserved
// and is now stale by three values: 0x08, 0x09 and this one.)
let VEDA_CAUSE_RESIDENCY_FAULT : bits(5) = 0b01010 // 0x0A
// The OBJECT's own policy refused this caller. Its own cause, not a reuse of
// OWNER_VIOLATION (0x06, "another HART holds it") or REGION_FAULT (0x09, "that
// domain's table is paged out"): those two ask software to release something or
// to page something in. This one asks for nothing, because the caller was never
// entitled to the object at all.
let VEDA_CAUSE_DOMAIN_VIOLATION : bits(5) = 0b01011 // 0x0B
// A store reached a copy-on-write object. ITS OWN CAUSE, and this is a
// deliberate departure from DESIGN_02, which proposed reusing the store-permission
// violation (0x13).
//
// The handler has to tell two situations apart: "this program has a real bug,
// it may not write here" and "this is copy-on-write, make a private copy and
// retry". They demand opposite responses. Reusing 0x13 collapses them, and
// there is no instruction that reads an ODT entry, so the handler cannot even
// inspect the cow bit to disambiguate. It would end up turning every genuine
// permission fault into a silent private copy -- converting a security fault
// into a performance feature. Same argument that gave residency its own cause.
let VEDA_CAUSE_COW_FAULT : bits(5) = 0b01100 // 0x0C

function veda_xtval(cap_idx : bits(4), cause : bits(5)) -> xlenbits = {
  // Deliberately avoids the two-argument `zero_extend(bits, width)` form --
  // verified this does not exist as a general builtin in the real Sail
  // stdlib (checked toolchain/opam-root/.../share/sail/lib directly; only
  // a differently-named `sail_zero_extend`, RVFI-specific, takes a width
  // argument). Uses the single-arg, context-inferred form throughout,
  // matching extensions/I/base_insts.sail's own real `extend_value`.
  let cap_idx5 : bits(5) = zero_extend(cap_idx);
  zero_extend(cap_idx5 @ cause)
}

function veda_trap(cap_idx : vcapidx, cause : bits(5)) -> ExecutionResult = {
  // Milestone 14 (PCC_COMPARTMENT_DESIGN.md): every real Veda-Core
  // hard-trap must save the live compartment bounds and reset to
  // unbounded before the trap actually fires -- real CHERI's own
  // "Exception Code Capability" requirement (CHERI ISA spec §3.4.7): a
  // trap handler must run in a trusted, unconstrained context, not be
  // blocked by whatever OCInvoke-narrowed bounds happened to be active
  // when the violation occurred.
  // R12: the inline save is REMOVED. It is now performed once, at the
  // single trap chokepoint (handle_trap_extension), which sys_control
  // calls unconditionally in both its Machine and Supervisor arms before
  // prepare_trap_vector -- i.e. before the handler's first fetch, which is
  // the ordering Milestone 21 depends on. The requirement quoted above is
  // therefore still met, one level down.
  //
  // THIS LINE WAS THE R12 WRITE VECTOR. The confirmed proof-of-concept
  // takes its nested trap through an ordinary capability violation, which
  // arrives here -- and the unconditional capture then copied the
  // already-reset PCC over the outer compartment's saved bounds.
  let Vcapidx(idx) = cap_idx;
  trap(make_sync_exception(E_Extension(()), veda_xtval(idx, cause)))
}

// Bind-mode field, VEDA_CORE_SPEC.md Section 4: only imm[1:0] used.
enum veda_bind_mode = {VEDA_BIND, VEDA_BIND_NOTRAP, VEDA_REBIND, VEDA_BIND_RESERVED}

mapping encdec_veda_bind_mode : veda_bind_mode <-> bits(2) = {
  VEDA_BIND          <-> 0b00,
  VEDA_BIND_NOTRAP   <-> 0b01,
  VEDA_REBIND        <-> 0b10,
  VEDA_BIND_RESERVED <-> 0b11,
}

union clause instruction = VEDA_BINDINST : (bits(2), regidx, vcapidx)

mapping clause encdec = VEDA_BINDINST(mode, rs1, rd)
  <-> 0b0000000000 @ mode @ encdec_reg(rs1) @ 0b101 @ 0b0 @ encdec_vcap(rd) @ 0b0001011
  when currentlyEnabled(Ext_Veda)

function clause execute VEDA_BINDINST(mode_bits, rs1, rd) = {
  let mode = encdec_veda_bind_mode(mode_bits);
  // Object_ID is now 44 bits (Phase 1 increment 2, the 256-bit respec).
  // rs1 is an ordinary GPR -- chosen originally so this width is never
  // hardcoded into the instruction ENCODING -- so this slice is the only
  // place the width is hardcoded at all, and 44 bits still fits easily
  // inside an xlenbits GPR value on RV64 (the extension is RV64-gated;
  // see DESIGN_01 decision 7).
  let object_id_gpr64 : bits(64) = zero_extend(X(rs1));
  let object_id = object_id_gpr64[43..0];
  let rdno = vcapidx_to_vcapno(rd);
  // DESIGN_08 -- region residency gate, BEFORE the ODT lookup. If the object's
  // domain (region = Object_ID[43:24]) is not resident, Object-Bind raises an
  // explicit REGION_FAULT and does not proceed -- a bounded, recoverable event
  // (page the domain in and retry), never a silent resolution. The current
  // domain is always resident (you are executing in it), so intra-domain binds
  // -- every pre-DESIGN_08 object, all region 0 -- never take this path. This
  // is a hard trap for ALL bind modes on purpose: a paged-out region is not a
  // "manipulate" soft-fail condition (Tag-clear would wrongly report
  // not-found); it must fault to the pager regardless of mode.
  let region = object_id[43 .. 24];
  if not(veda_region_is_resident(region)) then veda_trap(rd, VEDA_CAUSE_REGION_FAULT)
  else {
  let e = odt_lookup(object_id);
  // Milestone 12 (VEDA_CORE_SPEC.md §4.1): an object with no live owner
  // yet, or one this same hart already owns, is fair game -- claiming it
  // (or re-claiming it, idempotently) is exactly what a successful
  // Bind/Rebind does below. `mhartid` is a real, already-existing
  // architectural register (core/sys_regs.sail) -- not a new one
  // invented for this purpose -- truncated to the same 8-bit width
  // `owner_hart` itself uses (veda_types.sail's own real, bounded
  // 256-hart design ceiling).
  let owner_ok : bool = (e.owner_hart == VEDA_OWNER_UNOWNED) | (e.owner_hart == mhartid[7..0]);
  // The real claim, shared by both the Bind and Rebind success paths
  // below: every field except owner_hart carries over from the ODT's
  // own existing entry unchanged -- this is a claim, not a repopulate.
  let claimed_entry : odt_entry = struct {
    valid      = e.valid,
    Base       = e.Base,
    Length     = e.Length,
    Perms      = e.Perms,
    generation = e.generation,
    owner_hart = mhartid[7..0],
    retired    = e.retired,
    // DESIGN_02: CARRY OVER, and this one line is the highest-consequence
    // choice in the increment. A claim is not a repopulate -- taking
    // ownership of an object says nothing about whether its contents are in
    // memory. Writing `true` here would let any Bind mark any object
    // resident, which defeats the entire mechanism in one word; writing
    // `false` would make the second access to every object fault, breaking
    // every dereferencing test. Only the carry-over is right.
    resident   = e.resident,
    // Claiming an object for this hart must not alter its POLICY.
    owner_domain = e.owner_domain,
    cow = e.cow,
  };

  // DESIGN_02 -- OBJECT residency gate. Guarded on `e.valid` so the
  // ordering invariant holds: a never-populated slot is now BOTH invalid
  // and non-resident, and "never existed" (0x05) must keep winning over
  // "paged out" (0x0A). Stated positively: a residency fault means the
  // object EXISTS and is merely absent from memory -- recoverable, and the
  // handler knows to page it in rather than give up.
  //
  // A HARD TRAP FOR ALL BIND MODES, exactly like the region gate above and
  // for the identical reason: a paged-out object is not a "manipulate"
  // soft-fail condition. If Bind-NoTrap or Rebind merely cleared Tag here,
  // the caller would be told "no such object" and the pager would never be
  // invoked -- a live object would look permanently destroyed.
  // ═══ PER-OBJECT BIND AUTHORITY ═══
  //
  // The object itself says who may bind it. Three ways to pass: the object is
  // OPEN (VEDA_DOMAIN_ANY, which is how every object is created, so this
  // changes nothing until software narrows one); the caller is in no
  // compartment at all (boot code and trap handlers -- the bootstrap and the
  // pager); or the caller's domain matches.
  //
  // PER-OBJECT, NOT PER-REGION, and that is the whole lesson of the retracted
  // R17. A region-granular rule broke the RETURN PATH: a compartment's caller
  // lives in another domain by definition, so forbidding cross-domain Bind made
  // compartments one-way and livelocked a test. Here the return object is left
  // open while its neighbours are narrowed -- which is what legitimate sharing
  // actually looks like.
  //
  // The subject is veda_pcc_object, never veda_current_region: that register is
  // zero at reset and reset again on every trap, and region zero is ALSO a real
  // domain, so "no domain" and "domain 0" would be one value. PCC's name has an
  // out-of-band NONE no real object can hold.
  //
  // BEFORE residency, deliberately. Residency says "page this in"; this says
  // "you were never entitled". Telling a caller with no right to the object to
  // go run the pager is worse than useless -- it is a hint about an object that
  // is none of its business. Same ordering argument DESIGN_02 used to put
  // residency last among the entry-derived tests.
  if not(veda_bind_domain_ok(e.owner_domain)) then veda_trap(rd, VEDA_CAUSE_DOMAIN_VIOLATION)
  else if e.valid & not(e.resident) then veda_trap(rd, VEDA_CAUSE_RESIDENCY_FAULT)
  else

  match mode {
    VEDA_BIND_RESERVED => Illegal_Instruction(),

    VEDA_REBIND => {
      // VEDA_CORE_SPEC.md Section 4: Rebind on a currently-sealed capability
      // register soft-fails (Tag cleared, ODT refresh skipped) rather than
      // trapping -- it "manipulates" the register, it doesn't "use" the
      // object, matching Section 1's manipulate-vs-use split. The same
      // "manipulate, not use" reasoning extends to a wrong-owner ODT
      // entry (Milestone 12): Rebind never traps for ANY failure reason,
      // owner mismatch included -- it joins the object-not-found and
      // already-sealed cases in the same uniform soft-fail branch below.
      let cur = C(rdno);
      if isSealedCap(cur) then {
        wCTag(rdno, false);
        RETIRE_SUCCESS
      } else if e.valid & owner_ok then {
        odt_write(object_id, claimed_entry);
        // Increment 3: Base and Length now come straight across -- the ODT
        // entry is as wide as the capability. Only `generation` is still
        // bridged by a zero-extend, because the ODT's own generation stays
        // 8 bits until its own increment. flags is minted as zeros
        // (opaque/reserved).
        wC(rdno, struct {
          Object_ID  = object_id,
          Base       = e.Base,
          Length     = e.Length,
          Offset     = cur.Offset, // preserved across relocation, Section 4
          // DESIGN_02's own correction: a capability handed out with store
          // stripped is only ADVISORY, because the holder can re-Bind the name
          // and get a fresh, fully-permissioned one. So the attenuation has to
          // happen HERE, where the entry is the authority and no re-derivation
          // can escape it.
          Perms      = veda_bind_perms(e),
          otype      = UNSEALED_OTYPE,
          generation = e.generation,  // now same width (24) -- no bridge needed
          flags      = zeros(),
        });
        wCTag(rdno, true);
        RETIRE_SUCCESS
      } else {
        wCTag(rdno, false);
        RETIRE_SUCCESS
      }
    },

    // VEDA_BIND / VEDA_BIND_NOTRAP -- Sail match arms take exactly one
    // pattern each (no comma/pipe-separated alternatives, confirmed via a
    // real compiler error, not assumed), so this catch-all covers both of
    // the two remaining veda_bind_mode values (VEDA_REBIND and
    // VEDA_BIND_RESERVED are already handled above) and branches inside
    // the body instead.
    _ => {
      if e.valid & owner_ok then {
        odt_write(object_id, claimed_entry);
        // Same as the Rebind path above; fresh Bind starts at Offset 0.
        wC(rdno, struct {
          Object_ID  = object_id,
          Base       = e.Base,
          Length     = e.Length,
          Offset     = zeros(),
          // DESIGN_02's own correction: a capability handed out with store
          // stripped is only ADVISORY, because the holder can re-Bind the name
          // and get a fresh, fully-permissioned one. So the attenuation has to
          // happen HERE, where the entry is the authority and no re-derivation
          // can escape it.
          Perms      = veda_bind_perms(e),
          otype      = UNSEALED_OTYPE,
          generation = e.generation,  // now same width (24) -- no bridge needed
          flags      = zeros(),
        });
        wCTag(rdno, true);
        RETIRE_SUCCESS
      } else if e.valid then {
        // A live object, owned by a DIFFERENT hart -- a real, genuine
        // access-control violation, distinct in kind from "object not
        // found" (that object genuinely exists; this hart simply isn't
        // its owner). Bind-NoTrap still soft-fails here too, matching
        // its own established convention for every other failure
        // reason; plain Bind hard-traps, the first real consumer of
        // cause = 0x06.
        if mode == VEDA_BIND_NOTRAP then {
          wC(rdno, zero_capability);
          wCTag(rdno, false);
          RETIRE_SUCCESS
        } else {
          veda_trap(rd, VEDA_CAUSE_OWNER_VIOLATION)
        }
      } else if mode == VEDA_BIND_NOTRAP then {
        wC(rdno, zero_capability);
        wCTag(rdno, false);
        RETIRE_SUCCESS
      } else {
        veda_trap(rd, VEDA_CAUSE_OBJECT_NOT_FOUND)
      }
    },
  }
  }  // close the DESIGN_08 region-residency `else`
}

mapping veda_bind_mnemonic : veda_bind_mode <-> string = {
  VEDA_BIND          <-> "veda.bind",
  VEDA_BIND_NOTRAP   <-> "veda.bind.notrap",
  VEDA_REBIND        <-> "veda.rebind",
  VEDA_BIND_RESERVED <-> "veda.bind.reserved",
}

mapping clause assembly = VEDA_BINDINST(mode_bits, rs1, rd)
  <-> veda_bind_mnemonic(encdec_veda_bind_mode(mode_bits)) ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ reg_name(rs1)
