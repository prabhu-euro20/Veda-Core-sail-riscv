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
  // Object_ID widened from 16 to 23 bits this pass (VEDA_CORE_SPEC.md
  // Section 2/5.1, SCALING_BARRIERS_RESEARCH.md Section 3) -- rs1 is an
  // ordinary GPR (Section 4 of the spec: chosen specifically so this
  // width is never hardcoded into the instruction encoding), so this
  // slice is the only place the width was actually hardcoded, and it
  // still fits easily inside an xlenbits GPR value.
  let object_id = X(rs1)[22..0];
  let rdno = vcapidx_to_vcapno(rd);
  let e = odt_lookup(object_id);

  match mode {
    VEDA_BIND_RESERVED => Illegal_Instruction(),

    VEDA_REBIND => {
      // VEDA_CORE_SPEC.md Section 4: Rebind on a currently-sealed capability
      // register soft-fails (Tag cleared, ODT refresh skipped) rather than
      // trapping -- it "manipulates" the register, it doesn't "use" the
      // object, matching Section 1's manipulate-vs-use split.
      let cur = C(rdno);
      if isSealedCap(cur) then {
        wCTag(rdno, false);
        RETIRE_SUCCESS
      } else if e.valid then {
        wC(rdno, struct {
          Object_ID = object_id,
          Base      = e.Base,
          Length    = e.Length,
          Offset    = cur.Offset, // preserved across relocation, Section 4
          Perms     = e.Perms,
          otype     = UNSEALED_OTYPE,
          Reserved  = e.generation,
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
      if e.valid then {
        wC(rdno, struct {
          Object_ID = object_id,
          Base      = e.Base,
          Length    = e.Length,
          Offset    = zeros(),
          Perms     = e.Perms,
          otype     = UNSEALED_OTYPE,
          Reserved  = e.generation,
        });
        wCTag(rdno, true);
        RETIRE_SUCCESS
      } else if mode == VEDA_BIND_NOTRAP then {
        wC(rdno, zero_capability);
        wCTag(rdno, false);
        RETIRE_SUCCESS
      } else {
        veda_trap(rd, VEDA_CAUSE_OBJECT_NOT_FOUND)
      }
    },
  }
}

mapping veda_bind_mnemonic : veda_bind_mode <-> string = {
  VEDA_BIND          <-> "veda.bind",
  VEDA_BIND_NOTRAP   <-> "veda.bind.notrap",
  VEDA_REBIND        <-> "veda.rebind",
  VEDA_BIND_RESERVED <-> "veda.bind.reserved",
}

mapping clause assembly = VEDA_BINDINST(mode_bits, rs1, rd)
  <-> veda_bind_mnemonic(encdec_veda_bind_mode(mode_bits)) ^ spc() ^ vcap_name(encdec_vcap(rd)) ^ sep() ^ reg_name(rs1)
