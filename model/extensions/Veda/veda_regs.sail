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

// Minimal OS kernel Milestone A (MINIMAL_OS_KERNEL_DESIGN.md): the TSC
// (Trusted Stack Capability) -- Veda-Core's own second Special Capability
// Register, term-for-term adapted from real CHERIoT's own `mtdc` (M-mode
// Trusted Data Capability, CHERIoT RTOS architecture.md's own real
// switcher description, read in full: "the switcher... store[s] a
// capability to the current thread's trusted stack and register-save
// area in the mtdc capability special register"). A real, tagged
// capability -- not a plain CSR -- for the identical real reason
// `veda_oda` above is one: it must carry Base/Length/Perms/Tag, none of
// which a 64-bit CSR can hold. Kept as its own top-level register (not
// `cr16`), matching `veda_oda`'s own established precedent: a genuinely
// different architectural role (the switcher's own anchor to the
// current thread's register-save area) from any general-purpose
// capability register.
register veda_tsc : capability
register veda_tsc_tag : bool

// SSC (Stack-Spill Capability) -- Veda-Core's own third Special Capability
// Register, added to let ordinary compiled C's ABI-mandated callee-saved
// -register spills/reloads route through real OCL.D/OCS.D checks instead
// of raw sd/ld (which Milestone 19's purecap rule unconditionally traps
// inside a live compartment -- TOOLCHAIN_MILESTONE_10_RESULTS.md's own
// major finding). Deliberately NOT persistent-and-OCInvoke/OCRETURN
// -transparent like veda_oda/veda_tsc above: VEDA_OCINVOKE and
// VEDA_OCRETURN (veda_cap_insts.sail) both clear (untag) this register on
// every successful compartment-boundary crossing -- a real, necessary
// asymmetry from ODA/TSC found by an independent design review before any
// code was written (an SSC following ODA/TSC's own "untouched by
// OCInvoke" convention would let a callee silently inherit full
// read/write access to the caller's entire stack region). The entered
// compartment re-establishes its own SSC via an explicit OSpecialRW, the
// identical already-established pattern ODA/TSC themselves use.
register veda_ssc : capability
register veda_ssc_tag : bool

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
// Increment 3: the sentinel is all-ones in the WIDENED Length field, so
// it stays semantically "maximum possible length = no compartment", the
// same meaning it always had. Its numeric VALUE necessarily changes with
// the width (0xFFFF -> 0xFFFFFFFFFF); keeping the old number would have
// made a legitimate 65535-byte compartment read as unbounded, which is a
// real hole, so the value change is deliberate and tests assert the new
// one.
let VEDA_PCC_UNBOUNDED : bits(40) = 0xFFFFFFFFFF
register veda_pcc_base : bits(56)
register veda_pcc_length : bits(40)
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
register veda_mepcc_base : bits(56)
register veda_mepcc_length : bits(40)

// ═══════════════════════════════════════════════════════════════════════
//  R12 (DESIGN_07 Tier H) -- OUT-OF-BAND TRAP NESTING STATE.
//
//  WHY AN OUT-OF-BAND BIT AT ALL. VEDA_PCC_UNBOUNDED was being made to
//  mean two different things: "this compartment has no bounds" (a real
//  runtime state) and "nothing was saved" (what the restore guard read it
//  as). Those are different facts, and an object may legitimately have
//  Length == VEDA_PCC_UNBOUNDED -- odt_entry.Length is bits(40) and
//  Populate-Fast writes it unrestricted, so the collision is reachable,
//  not theoretical. Conflating them IS R12.
//
//  This follows CHERI, which faced the same choice and made the opposite
//  one: MEPCC there is a Special Capability Register and therefore tagged,
//  and the specification states both "NULL Does Not Have the Tag Bit Set"
//  and "The length of NULL is MAXINT". CHERI's null carries the same
//  maximal length our sentinel uses and is distinguished OUT OF BAND.
//
//  WHY A COUNTER AND NOT JUST A VALIDITY BIT. A bit answers "is a save
//  outstanding" but not "is this the xret that owns it". With one slot and
//  a bare validity bit, a nested trap leaves the outer save intact and the
//  INNER xret then consumes it -- installing compartment bounds into the
//  still-running handler. Same escape, one level up. Only a depth notion
//  distinguishes the outermost xret from an inner one.
//
//  WHY THIS IS ONLY NOW IMPLEMENTABLE. A counter is meaningless unless it
//  increments exactly once per trap. Until R12 there were NINE callers of
//  veda_pcc_save_and_reset, five of them CSR-escape gates that save inline
//  and then raise a real exception which reaches the chokepoint as well --
//  so one logical trap could reach the save twice. Those eight inline
//  calls are removed in this same change; the chokepoint is now the sole
//  caller, and sys_control invokes it unconditionally in both arms. THAT
//  is what makes "once per trap" true, and the counter honest.
//
//  NOT SOFTWARE-WRITABLE, deliberately. veda_mepcc_base/_length are
//  writable via CSR 0x7C2/0x7C3 while PCC is unbounded, so a handler can
//  already forge the saved VALUE. It must not additionally be able to
//  forge the OCCUPANCY, or the mechanism is defeated by the software it
//  exists to constrain. There is no write_CSR clause for these.
register veda_trap_depth : bits(8)
register veda_trap_poison : bool

// Milestone 14: shared by both real hard-trap paths that narrow PCC
// away from a live compartment -- `veda_trap()` (every ordinary
// Veda-Core "use"-family violation) and the new PCC-bounds-violation
// path (veda_pcc.sail, routed through `handle_exception` directly since
// it fires outside the normal per-instruction execute dispatch). Saves
// the live compartment bounds so software can restore them later, then
// resets to unbounded so the trap handler itself runs in a trusted,
// unconstrained context -- real CHERI's own "Exception Code Capability"
// requirement (CHERI ISA spec §3.4.7).
// R10: the CRBR halves of the trap/xret discipline. Forward-declared here
// because their bodies need the Region Table and CRBR registers, which are
// declared further down this file (Sail requires declaration before use);
// the bodies live directly after veda_crbr_load below.
// R12: forward-declared for the same reason the CRBR pair above is -- it
// reads veda_current_region, which is declared further down this file, and
// Sail requires declaration before use. The type checker caught this
// directly; it is the kind of ordering error TL-Verilog accepts silently,
// which is why the Sail layer is written first.
val veda_trap_level_has_context : unit -> bool
val veda_trap_frame_abandon : unit -> unit
val veda_crbr_save_and_reset : unit -> unit
val veda_crbr_restore_on_xret : unit -> unit

function veda_pcc_save_and_reset() -> unit = {
  // R12. Capture ONLY on the outermost trap. At depth > 0 an outer save is
  // already held and must not be overwritten -- that overwrite was the
  // confirmed defect.
  if veda_trap_depth == zeros() then {
    veda_mepcc_base = veda_pcc_base;
    veda_mepcc_length = veda_pcc_length;
  } else {
    // A nested trap. Ordinarily harmless: the handler runs with PCC
    // already reset, so the level being entered has no context worth
    // keeping and can be reconstructed on the way out.
    //
    // The exception is the case that makes a bare guard insufficient. A
    // handler running unbounded may legitimately narrow itself -- by
    // OCInvoke, or by writing 0x7C0/0x7C1, which the CSR gates permit
    // precisely while unbounded -- and then fault. That level's context is
    // real, one slot cannot hold it, and a counter cannot reconstruct it.
    // Record that the chain is unreconstructible and fail closed on the
    // way out rather than guessing.
    if veda_trap_level_has_context() then veda_trap_poison = true
  };
  // Saturate rather than wrap. A wrapped depth would alias an inner xret
  // onto the outermost one and hand a compartment's bounds to a handler --
  // the identical failure this mechanism exists to prevent. At the ceiling
  // the chain is no longer countable, so it is no longer reconstructible.
  if veda_trap_depth == 0xFF then veda_trap_poison = true
  else veda_trap_depth = veda_trap_depth + 1;
  veda_pcc_base = zeros();
  veda_pcc_length = VEDA_PCC_UNBOUNDED;
  // R10: the CRBR half of the same trap discipline, folded into this one
  // function so every existing save site (veda_trap, the fetch/data check
  // errors, the CSR write gates, handle_trap_extension) inherits it at
  // once -- the Milestone-21 lesson was precisely that per-site additions
  // miss paths.
  veda_crbr_save_and_reset();
}

// Automatic restore-on-mret/sret counterpart, matching real CHERI's own
// mepcc-unseal-on-mret precedent (CHERI-RISC-V spec §12.2.19/§4.7.7:
// "MRET unseals mepcc and writes the result into pcc", unconditional on
// cause). Gated on veda_mepcc_length's own "was anything saved here"
// sentinel, mirroring this project's own established "conditional, not
// unconditional" convention (veda_pcc_save_and_reset()'s own capture is
// itself conditional, for the identical reason).
//
// Honest note on this guard's real, empirically-checked scope, per this
// project's own mutation-test discipline: because ALL THREE of this
// project's own pre-existing save call sites (veda_trap(),
// ext_handle_fetch_check_error, ext_handle_data_check_error, Milestone
// 14) already save unconditionally whenever a trap is taken from a
// bounded context -- not just this function's own Milestone-21-added
// handle_trap_extension call site -- veda_mepcc_length is, in every
// currently-reachable scenario tried, either genuinely fresh (a real
// save just happened for THIS trap) or genuinely the untouched-since
// -reset/self-consumed default (nothing to restore, and live PCC is
// already unbounded, so copying the default over it is a harmless
// no-op regardless). A dedicated mutation-test attempt to construct a
// scenario where the guard's presence vs. absence is observable (a
// direct, non-OCInvoke CSR write establishing bounded live PCC, timed
// so no trap has fired yet) could not be built: any trap taken from
// that bounded state immediately triggers a fresh save via the
// pre-existing Milestone-14 call sites regardless of this function's
// own guard, before this function is even reached -- confirmed by
// removing the guard entirely and re-running the full self-check
// regression, which stayed at 61/61 with zero observable difference.
// The guard is kept because it matches this project's own stated
// design principle and imposes no cost, not because a reachable
// scenario currently depends on it -- stated honestly, not left as an
// unverified claim.
//
// Self-consuming regardless: after copying veda_mepcc_base/_length into
// live PCC, immediately reset them back to the unbounded sentinel, so a
// saved value is never applied to more than one mret/sret.
function veda_pcc_restore_on_xret() -> unit = {
  // R12. The old guard tested veda_mepcc_length against the sentinel --
  // a VALIDITY question answered with an in-band VALUE, which is exactly
  // what made a clobbered save read as "nothing was saved" and resume a
  // compartment UNBOUNDED. Occupancy is now carried out of band by depth.
  if veda_trap_depth != zeros() then {
    veda_trap_depth = veda_trap_depth - 1;
    if veda_trap_depth == zeros() then {
      if veda_trap_poison then {
        // FAIL CLOSED. The chain could not be reconstructed, so we do not
        // guess at a context. A zero-length PCC faults on the very next
        // fetch, before any instruction executes -- loud, and incapable of
        // granting anything. The alternative, restoring the reset context,
        // would hand unbounded authority to a level that was narrowed:
        // R12 again, one level up.
        //
        // Direction check against the ratified precedent: RISC-V's
        // Smdbltrp answers this same condition with a critical-error state
        // that updates no architectural state at all. Denying and
        // continuing is strictly gentler than that, and no weaker in
        // direction.
        veda_pcc_base = zeros();
        veda_pcc_length = zeros();
      } else {
        veda_pcc_base = veda_mepcc_base;
        veda_pcc_length = veda_mepcc_length;
      };
      veda_mepcc_base = zeros();
      veda_mepcc_length = VEDA_PCC_UNBOUNDED;
      veda_trap_poison = false;
    } else {
      // Unwinding an inner level. Its context was the reset context by
      // construction -- every trap resets PCC before the handler runs --
      // so it is reconstructed rather than stored. This is why one slot
      // plus a counter is LOSSLESS here and not an approximation.
      if veda_trap_poison then {
        veda_pcc_base = zeros();
        veda_pcc_length = zeros();
      } else {
        veda_pcc_base = zeros();
        veda_pcc_length = VEDA_PCC_UNBOUNDED;
      }
    }
  };
  // R10: the CRBR restore rides the same xret, but under its OWN sentinel
  // guard (VEDA_REGION_NONE), deliberately NOT inside the mepcc guard
  // above. The two captures have different conditions (mepcc: PCC was
  // bounded; CRBR: region was non-root), so coupling the restores would
  // strand a saved region whenever a trap was taken from a non-root domain
  // whose PCC happened to be unbounded -- the two disciplines must stay
  // independent to stay individually self-consuming.
  veda_crbr_restore_on_xret();
}

// Real, empirically-confirmed privilege-escalation gap, found while
// explaining the mechanism above, not invented speculatively: mtvec
// (0x305, the standard RISC-V trap-vector CSR) has never had any
// compartment-aware gating -- MILESTONE_20_RESULTS.md already found and
// documented this, and at the time judged it not independently
// exploitable, because back then an *ordinary* trap left veda_pcc_length
// narrowed across the trap, so a handler placed outside the compartment's
// own bounds would immediately fetch-fault itself. veda_pcc_restore_on_xret's
// own sibling, the handle_trap_extension hook above (Milestone 21,
// universal PCC-reset-on-any-trap), deliberately removed exactly that
// backstop for good, independent functional reasons -- but nobody went
// back and re-examined the mtvec gap in light of it. A live PoC
// (sail_tests/vc_pcc_mtvec_escape_neg.S), traced with --trace-instr,
// empirically confirmed the composed result before this fix existed: a
// bounded compartment can (1) csrw mtvec to point at attacker-chosen
// code with zero trap, (2) trigger any ordinary trap (a plain ecall
// suffices) -- and that code then runs with fully unbounded PCC, fetched
// from an address the CPU trace showed was outside the compartment's own
// bounds yet raised no fetch fault, proving PCC had already been reset by
// the time of that fetch.
//
// Fix mirrors this exact codebase's own real, already-shipped precedent
// for "gate a CSR on state defined in a different module" --
// extensions/Stateen/stateen_access_checks.sail's stateen_allows_CSR_access,
// ANDed into check_CSR (sys/sys_control.sail) as an independent conjunct
// alongside is_CSR_accessible, not folded into is_CSR_accessible itself.
// That precedent was followed deliberately over the alternative (editing
// mtvec's own is_CSR_accessible clause or write_CSR clause directly in
// exceptions/sys_exceptions.sail, both base-model files) for two real
// reasons: (1) Sail's scattered write_CSR only allows one clause per CSR
// address project-wide -- mtvec's is already claimed in
// exceptions/sys_exceptions.sail, so a second Veda-side write_CSR(0x305,...)
// clause is not an option, unlike the previously-unclaimed 0x7C0-0x7C5
// range Milestone 20 gated directly; (2) editing sys_exceptions.sail's
// existing is_CSR_accessible(0x305,_,_) clause to reference
// veda_pcc_length would put Veda-specific state into a base-model file,
// the same real circular-module-dependency problem Stateen's own header
// comment names as its reason for using a separate hook instead.
//
// Real official CHERI-RISC-V precedent (specs/cheri-architecture.pdf,
// Table 4.3: MTCC, "extends mtvec", Access=ASR; Section 4.3.5: reading or
// writing any CSR requires PCC.perms.Access_System_Registers) gates BOTH
// reads and writes of mtvec/MTCC. This fix deliberately gates writes only,
// diverging from that broader rule to stay consistent with this
// project's own already-stated, twice-applied principle (Milestone 20's
// veda_pcc_*/veda_mode CSRs, and the query-family instructions before
// them): capability/control metadata is always inspectable, only
// mutation is restricted -- reading mtvec does not, by itself, grant any
// new capability or help bypass anything a compartment doesn't already
// know from its own bounds.
function veda_allows_CSR_access(csr : csreg, priv : Privilege, access_type : CSRAccessType) -> bool =
  match csr {
    0x305 => (access_type == CSRRead) | (veda_pcc_length == VEDA_PCC_UNBOUNDED),
    _     => true,
  }

// Milestone 18 (real, measured motivation: IMMEDIATE_LIMIT_INVESTIGATION --
// RV64I's 12-bit immediate forces a full 6-instruction `li` per ODT-Populate
// descriptor, and a real, dedicated benchmark showed a software-only `la`
// -based workaround saves only ~5%, since Base still has to be shifted into
// the descriptor's upper 32 bits regardless of how it's loaded). `veda_attr`
// holds Length(bits 31..16)/Perms(bits 15..0) -- the *reusable* half of a
// descriptor, set once via the real, already-working, unmodified CSRRW (no
// new "set" instruction needed) and then read directly by
// `VEDA_ODT_POPULATE_FAST` below for every object sharing that template.
// Reset to zero (harmless: an all-zero Length/Perms just makes the first
// fast-populated object real but permission-less until software actually
// sets this CSR, not a crash/undefined-behavior risk).
register veda_attr : bits(64)

// Milestone 19 (Veda-Purecap Enforcement): next free slot in the same
// real, RISC-V-spec-reserved M-mode custom range already used for
// 0x7C0-0x7C4 above -- same mechanism, not a new one. Bit 0 =
// veda_purecap: global "ordinary LOAD/STORE/AMO/etc. is illegal
// everywhere" flag, closing the real gap this milestone exists for (see
// veda_bind_insts.sail's VEDA_CAUSE_PURECAP_VIOLATION comment for the
// full reasoning). Bits 1-31 reserved for future mode bits, explicitly
// zero for now: read_CSR reports them as 0, write_CSR ignores them (only
// bit 0 is ever assigned from a write).
register veda_mode : bits(32)

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
// (read directly before writing this, not assumed). Milestone 18 reuses
// this exact same real range/mechanism for `veda_attr` at 0x7C4, the
// next free slot after Milestone 14's four.
mapping clause csr_name_map = 0x7C0 <-> "veda_pcc_base"
mapping clause csr_name_map = 0x7C1 <-> "veda_pcc_length"
mapping clause csr_name_map = 0x7C2 <-> "veda_mepcc_base"
mapping clause csr_name_map = 0x7C3 <-> "veda_mepcc_length"
mapping clause csr_name_map = 0x7C4 <-> "veda_attr"
mapping clause csr_name_map = 0x7C5 <-> "veda_mode"
// R10: read-only observability for the CRBR and its saved shadow. The
// whole reason R10 was a SILENT escape is that nothing ever observed the
// current region -- so exposing it (read-only) is the honest fix for the
// observability gap, and it is what lets a test assert the trap-save /
// mret-restore cycle directly instead of only inferring it. STRICTLY
// read-only, enforced at the accessibility gate below (writes are
// Illegal_Instruction, no write_CSR clause exists), so this adds NO new
// write surface -- unlike a writable CRBR CSR, which would be a
// Milestone-19/20-class self-escape (a live compartment CSRRW-ing its own
// ODT base re-points its whole namespace). Read-only matches this file's
// established "capability metadata is always inspectable" principle.
mapping clause csr_name_map = 0x7C6 <-> "veda_current_region"
mapping clause csr_name_map = 0x7C7 <-> "veda_saved_region"
// R12: read-only status for the trap-nesting state. Without it the depth
// and poison bits are architecturally invisible, and a handler cannot tell
// WHY a return was denied. Read-only by construction, following 0x7C6/7:
// software may already forge the saved mepcc VALUE via 0x7C2/0x7C3, and
// must not additionally be able to forge the OCCUPANCY.
mapping clause csr_name_map = 0x7C8 <-> "veda_trap_status"

function clause is_CSR_accessible(0x7C0, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C1, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C2, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C3, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C4, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C5, _, _) = currentlyEnabled(Ext_Veda)
// R10: read-only -- accessible ONLY for reads. A write attempt is
// inaccessible and traps Illegal_Instruction before any dispatch, which
// is why no write_CSR(0x7C6/0x7C7) clause exists or is needed.
function clause is_CSR_accessible(0x7C6, _, access_type) = currentlyEnabled(Ext_Veda) & (access_type == CSRRead)
function clause is_CSR_accessible(0x7C7, _, access_type) = currentlyEnabled(Ext_Veda) & (access_type == CSRRead)
function clause is_CSR_accessible(0x7C8, _, access_type) = currentlyEnabled(Ext_Veda) & (access_type == CSRRead)

function clause read_CSR(0x7C0) = veda_to_xlen(zero_extend(veda_pcc_base))
function clause read_CSR(0x7C1) = veda_to_xlen(zero_extend(veda_pcc_length))
function clause read_CSR(0x7C2) = veda_to_xlen(zero_extend(veda_mepcc_base))
function clause read_CSR(0x7C3) = veda_to_xlen(zero_extend(veda_mepcc_length))
function clause read_CSR(0x7C4) = veda_to_xlen(veda_attr)
function clause read_CSR(0x7C5) = zero_extend(veda_mode)
// read_CSR(0x7C6)/(0x7C7) are declared after the CRBR register
// declarations below -- Sail requires the register bound before a clause
// that reads it (the pcc CSRs above sit after veda_pcc_base for the same
// reason).

// Milestone 20 (real, empirically-confirmed vulnerability, not
// theorized): before this pass, all four of these writes were
// unconditional -- meaning code entered via a real OCInvoke (narrowed to
// its own Base/Length, veda_pcc_length != VEDA_PCC_UNBOUNDED) could
// simply `csrw 0x7c1, 0xFFFF` to widen its own compartment back to
// unbounded and escape, no trap, no restriction, using only instructions
// that already existed. Verified live via a real PoC run under
// sail_riscv_sim before this fix: a compartment narrowed to Length=0x40
// executed the ordinary CSR write and then continued executing PAST the
// original boundary with zero trap. Real CHERI's own actual rule
// (verified via its public documentation): "Reading or writing any CSR
// requires the Access_System_Registers permission on the PCC" -- Veda
// -Core had no equivalent gate at all for its own compartment-state
// CSRs. Fix: require `veda_pcc_length == VEDA_PCC_UNBOUNDED` (i.e. not
// currently inside a live compartment) before any of these four writes
// is allowed; otherwise call `veda_pcc_save_and_reset()` (the identical
// real discipline every other Veda hard-trap already follows, so the
// resulting trap handler runs unconstrained, not still narrowed) and
// return `Err(())` -- confirmed via direct read of
// extensions/Zicsr/zicsr_insts.sail's own `doCSR` dispatch
// (`Err(()) => Illegal_Instruction()`) and core/csr_begin.sail's real
// declared signature (`result(xlenbits, unit)`) that this is a real,
// already-proven, idiomatic hard-trap mechanism -- not a silent no-op,
// and not a new one invented for this purpose. Read access is
// deliberately NOT gated -- matches this file's own already-established
// "capability metadata is always inspectable" principle
// (veda_cap_insts.sail's query-family comment): code inside a
// compartment already knows its own bounds (it got there via the
// capability that defined them), so reading them back leaks nothing.
// `veda_mepcc_base`/`_length` (0x7C2/0x7C3) are gated identically, not
// just 0x7C0/0x7C1 -- the same escape generalizes trivially to forging
// the *saved* bounds a trap handler's own restore convention would later
// trust, a second real attack this same fix closes, not just the one the
// PoC directly demonstrated. `veda_attr` (0x7C4) is deliberately NOT
// gated here -- its sole consumer, VEDA_ODT_POPULATE_FAST, already has
// its own independent capability-authority gate (`veda_oda_authorized()`
// OR M-mode, Milestone 11), so a compartment rewriting `veda_attr` alone
// cannot use it for anything without separately satisfying that
// unrelated check -- considered and correctly excluded, not overlooked.
function clause write_CSR(0x7C0, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { Err(()) }
  else { let v64 : bits(64) = zero_extend(value); veda_pcc_base = v64[55..0]; Ok(veda_to_xlen(zero_extend(veda_pcc_base))) }
}
function clause write_CSR(0x7C1, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { Err(()) }
  else { let v64 : bits(64) = zero_extend(value); veda_pcc_length = v64[39..0]; Ok(veda_to_xlen(zero_extend(veda_pcc_length))) }
}
function clause write_CSR(0x7C2, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { Err(()) }
  else { let v64 : bits(64) = zero_extend(value); veda_mepcc_base = v64[55..0]; Ok(veda_to_xlen(zero_extend(veda_mepcc_base))) }
}
function clause write_CSR(0x7C3, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { Err(()) }
  else { let v64 : bits(64) = zero_extend(value); veda_mepcc_length = v64[39..0]; Ok(veda_to_xlen(zero_extend(veda_mepcc_length))) }
}
function clause write_CSR(0x7C4, value) = { veda_attr = zero_extend(value); Ok(veda_to_xlen(veda_attr)) }
// Milestone 19: M-mode-write-gated, explicitly, inside this clause --
// matching VEDA_OSPECIALRW's own established precedent
// (veda_cap_insts.sail) for "privileged Veda operations check
// cur_privilege explicitly in their own body," not any CSR-address
// -encoded privilege mechanism (which, noted honestly, does not
// independently gate 0x7C0-0x7C4 either -- a pre-existing gap this
// milestone matches consistently rather than silently fixing under a
// different milestone's own scope). A non-M-mode write is a silent
// no-op (CSR value unchanged), the safe failure direction (a non-M-mode
// write attempting to *disable* purecap mode simply fails to take
// effect) -- retained as-is; only the compartment-state check below is
// new (Milestone 20's own real Err(())/Illegal_Instruction mechanism,
// not a silent no-op -- the original comment here calling that
// "unavailable" was itself wrong, corrected via direct source read of
// core/csr_begin.sail's real declared write_CSR signature,
// result(xlenbits, unit), before writing Milestone 20's own fix above).
// Milestone 20: same real self-escape vector as 0x7C0-0x7C3 above --
// code inside a live compartment could `csrw 0x7c5, 0` to silently
// disable Milestone 19's own purecap enforcement out from under itself.
// Gated identically.
function clause write_CSR(0x7C5, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { Err(()) }
  else {
    if cur_privilege == Machine then veda_mode = zero_extend(value[0..0]);
    Ok(zero_extend(veda_mode))
  }
}

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

// Phase 1 increment 2 (DESIGN_01 decision 3): the capability now carries a
// full 44-bit Object_ID, but the modeled table stays a flat, BOUNDED window
// -- a vector(2^44) would be roughly 300 TiB and simply will not build. Ids
// at or above the modeled size read as "not found" (an empty entry, valid =
// false), which flows into the existing OBJECT_NOT_FOUND trap path with no
// new mechanism; writes to out-of-range ids are dropped for the same reason.
//
// This is an honest interim bound, not a claim that the namespace is small:
// the same "real, bounded, honestly-scoped" discipline the RTL already
// applies to its own 256-entry ODT, holding until the segmented-Object_ID
// trilemma (DESIGN_06) is designed. The explicit comparison before indexing
// is also what discharges Sail's own in-bounds proof obligation -- the index
// domain (2^44) and the array size (2^23) are now decoupled, so they must be
// reconciled by a real check rather than by assumption.
let VEDA_ODT_MODELED_ENTRIES = 8388608

// DESIGN_08 Sail experiment -- domain-segmented Object_ID. The single flat
// modeled ODT array (2^23 = VEDA_ODT_MODELED_ENTRIES entries) is partitioned
// into VEDA_REGION_MODELED regions of VEDA_LOCAL_MODELED entries each
// (8 x 2^20 = 2^23 exactly, so existing region-0 objects keep their old
// indices and the whole prior corpus is unaffected). In real hardware each
// region has its OWN physically-separate ODT and only resident ones consume
// DRAM; here they are laid out contiguously in the one modeled array, and
// `region_odt_base` is the base into it -- faithful, since region_odt_base is
// exactly a base offset in the real design too.
let VEDA_REGION_MODELED = 8
let VEDA_LOCAL_MODELED  = 1048576  // 2^20 modeled objects per region; 8 x this = 2^23

// The Region Table: flat, always-resident, one entry per modeled domain.
register veda_region_table : vector(8, region_entry) = vector_init(empty_region_entry)

// The Current-Region Base Register (CRBR, DESIGN_08 Section 4). A single
// architectural register, NOT a cache or TLB (no tags, no eviction, no
// fill-on-miss, no access history). It lets a bind to an object in the
// CURRENT domain skip the RT read entirely: intra-domain bind = one ODT read
// (no regression from the pre-DESIGN_08 single flat table), only a
// cross-domain bind pays the extra RT read. veda_current_region defaults to
// region 0, so every pre-DESIGN_08 test (all region-0 objects) stays on the
// one-read fast path and is byte-for-byte unaffected.
//
// R10 (DESIGN_07 Tier G): the CRBR is now genuinely LOADED at the two
// domain crossings (VEDA_OCINVOKE / VEDA_OCRETURN, veda_cap_insts.sail),
// under one rule with two clauses:
//
//   The CRBR is loaded ONLY from the Object_ID[43:24] of the code
//   capability being entered or returned to, and EVERY load is validated
//   through the Region Table -- never through the current-region
//   fast-path exemption below.
//
// The first clause makes the source unforgeable (a capability's Object_ID
// cannot be manufactured; only Bind mints one, and Bind is residency-
// gated). The second clause is what makes veda_region_is_resident's
// exemption sound BY CONSTRUCTION rather than by convention: the CRBR can
// only ever come to name a region the RT said was resident at load time.
// A load whose region is not RT-resident raises VEDA_CAUSE_REGION_FAULT
// and commits nothing.
register veda_current_region   : bits(20) = zeros()
register veda_current_odt_base : bits(56) = zeros()

// R10: the saved-CRBR pair for the trap/mret cycle, the structural twin of
// veda_mepcc_base/_length above. Region 0 is a LEGITIMATE region (the root
// domain every pre-DESIGN_08 test runs in), so "saved == 0" cannot mean
// "nothing saved" the way VEDA_PCC_UNBOUNDED does for mepcc -- the empty
// sentinel is instead an OUT-OF-WINDOW region value: 0xFFFFF is >=
// VEDA_REGION_MODELED, can never be current (every load is RT-validated,
// and out-of-window regions are never RT-resident), and so can never be
// confused with a real saved domain.
let VEDA_REGION_NONE : bits(20) = 0xFFFFF
register veda_saved_region      : bits(20) = 0xFFFFF
register veda_saved_region_base : bits(56) = zeros()

// R10: the RT-direct residency check used for CRBR LOADS. Deliberately a
// separate function from veda_region_is_resident below, and deliberately
// WITHOUT its current-region exemption: the exemption's soundness is
// exactly what a validated load establishes, so the load itself consulting
// the exemption would be circular -- a stale current region would validate
// its own successor. Out-of-window regions are not modeled and therefore
// not resident; in-window regions are resident iff the RT says so on BOTH
// bits (rt_valid gains its first-ever consumer here: a slot that has never
// been configured must fail closed even if its resident bit were somehow
// set).
function veda_region_rt_resident(region : bits(20)) -> bool = {
  let ru = unsigned(region);
  if ru >= VEDA_REGION_MODELED then false
  else veda_region_table[ru].rt_valid & veda_region_table[ru].region_resident
}

// R10: the validated CRBR load. Caller must have already checked
// veda_region_rt_resident (the two crossings trap with REGION_FAULT before
// calling this); the assert re-establishes the in-bounds fact across that
// caller boundary, the same discipline odt_lookup already uses. The PAIR
// is loaded together from the same RT entry -- region and base must never
// be written separately, or veda_odt_base_of would serve a mismatched base
// for the "current" region: silent cross-region ODT aliasing, strictly
// worse than the escape this mechanism closes.
function veda_crbr_load(region : bits(20)) -> unit = {
  let ru = unsigned(region);
  assert(ru >= 0 & ru < VEDA_REGION_MODELED);
  veda_current_region   = region;
  veda_current_odt_base = veda_region_table[ru].region_odt_base;
}

// R10: trap-entry half (body for the forward declaration next to
// veda_pcc_save_and_reset above, which calls this on every save site).
// Capture is conditional on a NON-ROOT domain being live: region 0 needs
// no save, because the reset target below IS region 0, so a restore-to-0
// is the identity. The guard is also what protects the saved value from a
// nested trap: the handler itself runs in region 0, so a second trap taken
// inside it captures nothing and cannot clobber the first trap's save --
// structurally the same protection the PCC side gets from its UNBOUNDED
// sentinel. The reset is UNCONDITIONAL, mirroring the PCC reset: the
// handler always runs in the root domain, never in the faulting
// compartment's -- otherwise a handler could page out the very region its
// own CRBR still names (the second escape path R10 records).
// R12: "does the level being entered carry context a counter cannot
// reconstruct?" Every trap resets PCC to unbounded and the region to root
// before the handler runs, so an inner level is normally reconstructible
// and needs no slot. The exception is a handler that narrowed ITSELF --
// by OCInvoke, or by writing 0x7C0/0x7C1, which the CSR gates permit
// precisely while unbounded -- and then faulted. That state is real, one
// slot cannot hold it, and reconstruction would be a guess.
//
// Both halves are tested because they move independently: OCInvoke changes
// PCC and region together, but a CSR write to 0x7C0/0x7C1 changes only
// PCC, and R10 established that an unbounded code object in a non-root
// region leaves PCC unbounded while the CRBR names that region.
// R12, and this is a Veda-Core-specific case with no RISC-V counterpart.
//
// A depth counter borrows RISC-V's assumption that a trap is left by an
// xret. This architecture has a SECOND exit: the trusted switcher leaves a
// trap handler by OCRETURN, and it is not free to do otherwise -- narrowing
// PCC with csrw and then falling through to a separate mret requires
// FETCHING that mret, which by then lies outside the just-narrowed bounds.
// The scheduler test records that as an empirically-found correctness gap,
// so the pattern is load-bearing, not incidental.
//
// The right semantics follow from what OCRETURN already does: it installs
// PCC from its own operand, so any saved context is superseded by
// definition. The frame is therefore ABANDONED, not restored -- discard
// the slot and drop the depth. Restoring instead would overwrite the
// bounds OCRETURN just legitimately installed.
//
// No authority is gained: the caller ends up with exactly the bounds of a
// sentry it already holds. And poison is cleared with the frame, because
// the chain it referred to has been deliberately discarded rather than
// unwound.
function veda_trap_frame_abandon() -> unit = {
  if veda_trap_depth != zeros() then {
    veda_trap_depth = veda_trap_depth - 1;
    if veda_trap_depth == zeros() then {
      veda_mepcc_base = zeros();
      veda_mepcc_length = VEDA_PCC_UNBOUNDED;
      veda_trap_poison = false;
    }
  }
}

function veda_trap_level_has_context() -> bool =
  veda_pcc_length != VEDA_PCC_UNBOUNDED | veda_current_region != zeros()

function veda_crbr_save_and_reset() -> unit = {
  if veda_current_region != zeros() then {
    veda_saved_region      = veda_current_region;
    veda_saved_region_base = veda_current_odt_base;
  };
  veda_current_region   = zeros();
  veda_current_odt_base = veda_region_table[0].region_odt_base;
}

// R10: xret half. Self-consuming exactly as the mepcc restore is: a saved
// domain is never applied to more than one mret/sret. The restore is
// INFALLIBLE by design -- it re-installs the saved pair verbatim, with no
// RT re-validation -- and that is sound TODAY for a checked reason, not an
// assumed one: the Region Table is immutable after reset (no RT-write
// instruction exists), so a pair that was RT-validated at its original
// load is still valid at restore. It is also FORCED: the mret path cannot
// raise a further trap in this model (veda_trap's result would be
// discarded in this unit context, and handle_exception from inside the
// hook would clobber mepc and then be overwritten by mret's own
// set_next_pc -- a livelock, verified by reading the dispatch in
// postlude/step.sail and sys/sys_control.sail before deciding this).
// HARD OBLIGATION recorded for the future RT-write instruction
// (DESIGN_07 R10, DESIGN_08 Section 9): it must refuse to clear residency
// on the CURRENT region and on any SAVED region, or this restore stops
// being sound the day that instruction lands.
function veda_crbr_restore_on_xret() -> unit = {
  if veda_saved_region != VEDA_REGION_NONE then {
    veda_current_region    = veda_saved_region;
    veda_current_odt_base  = veda_saved_region_base;
    veda_saved_region      = VEDA_REGION_NONE;
    veda_saved_region_base = zeros();
  }
}

// R10: the read-only CRBR observability CSR bodies, placed here (not up
// with the other read_CSR clauses) because Sail requires
// veda_current_region/veda_saved_region declared before a clause reads
// them. Accessibility and the name map are declared up with the others.
function clause read_CSR(0x7C6) = zero_extend(veda_current_region)
function clause read_CSR(0x7C7) = zero_extend(veda_saved_region)
// {poison, depth}: bit 8 is poison, bits 7..0 are the depth.
function clause read_CSR(0x7C8) = zero_extend([bool_to_bit(veda_trap_poison)] @ veda_trap_depth)

// Resolve a region's ODT base: the CRBR for the current region (the fast
// path, no RT read), the RT otherwise. Out-of-modeled-window regions get a
// base that odt_lookup/odt_write will reject as not-found.
function veda_odt_base_of(region : bits(20)) -> bits(56) = {
  if region == veda_current_region then veda_current_odt_base
  else {
    let ru = unsigned(region);
    if ru >= VEDA_REGION_MODELED then zeros() else veda_region_table[ru].region_odt_base
  }
}

// Is a region resident (its ODT table paged in)? The current region always
// is -- you cannot be executing in a domain whose table is not present. Any
// other in-window region is resident iff its RT bit says so; out-of-window
// regions are not modeled (handled as not-found, not as a fault).
function veda_region_is_resident(region : bits(20)) -> bool = {
  if region == veda_current_region then true
  else {
    let ru = unsigned(region);
    if ru >= VEDA_REGION_MODELED then false else veda_region_table[ru].region_resident
  }
}

// Two-step resolve: {region, local} -> a modeled global index, or None if
// either falls outside its modeled window. Bounding BOTH region and local is
// what guarantees global uniqueness -- a local that overflowed its window
// would otherwise alias the next region's slots.
function veda_odt_index(object_id : bits(44)) -> option(int) = {
  let region = object_id[43 .. 24];
  let local  = object_id[23 .. 0];
  let ru = unsigned(region);
  let lu = unsigned(local);
  if (region != veda_current_region & ru >= VEDA_REGION_MODELED) | lu >= VEDA_LOCAL_MODELED
  then None()
  else {
    let idx = unsigned(veda_odt_base_of(region)) + lu;
    if idx < VEDA_ODT_MODELED_ENTRIES then Some(idx) else None()
  }
}

// The assert re-establishes the in-bounds fact across the option boundary --
// veda_odt_index already guarantees it, but that proof does not survive
// through Some(idx), the identical "Failed to prove constraint" situation
// core/mem_metadata.sail already solves this exact way (its assert(idx >= 0 &
// idx < veda_tagstore_granules) before the tag-store access).
function odt_lookup(object_id : bits(44)) -> odt_entry =
  match veda_odt_index(object_id) {
    Some(idx) => { assert(idx >= 0 & idx < VEDA_ODT_MODELED_ENTRIES); veda_odt[idx] },
    None()    => empty_odt_entry,
  }

function odt_write(object_id : bits(44), e : odt_entry) -> unit =
  match veda_odt_index(object_id) {
    Some(idx) => { assert(idx >= 0 & idx < VEDA_ODT_MODELED_ENTRIES); veda_odt[idx] = e },
    None()    => (),
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
  // DESIGN_08 Sail experiment -- seed the Region Table FIRST, before any
  // object, because a cross-region odt_write resolves its base through the
  // RT. Region 0 = the current/default domain (its base is 0, so every
  // pre-DESIGN_08 region-0 object keeps its old index via the CRBR fast
  // path). Region 1 = a second RESIDENT domain, base 2^20, used to prove
  // global uniqueness ({region=1,local=k} is a different object than
  // {region=0,local=k}). Region 2 = a NON-RESIDENT domain, base 2^21, used
  // to prove the explicit REGION_FAULT (its object exists in backing but its
  // table is paged out). Regions 3-7 stay empty. The CRBR defaults to
  // region 0 / base 0, matching veda_current_region/veda_current_odt_base's
  // reset values.
  veda_region_table[0] = struct { rt_valid = true,  region_odt_base = to_bits(56, 0),       region_resident = true,  region_backing = zeros(), region_generation = zeros() };
  veda_region_table[1] = struct { rt_valid = true,  region_odt_base = to_bits(56, 1048576),  region_resident = true,  region_backing = zeros(), region_generation = zeros() };
  veda_region_table[2] = struct { rt_valid = true,  region_odt_base = to_bits(56, 2097152),  region_resident = false, region_backing = zeros(), region_generation = zeros() };
  // R10: region 3 is the rt_valid GATE fixture -- deliberately the
  // contradictory state {rt_valid = false, region_resident = true}: an
  // UNCONFIGURED slot whose resident bit happens to be set (garbage, or a
  // half-torn write). veda_region_rt_resident must fail CLOSED on it (check
  // rt_valid FIRST), so a CRBR load into region 3 REGION_FAULTs even though
  // its resident bit is true. rt_valid gains its first-ever consumer in the
  // R10 fix; without a slot in this exact state, dropping the rt_valid
  // conjunct would be an unobserved mutation.
  veda_region_table[3] = struct { rt_valid = false, region_odt_base = to_bits(56, 3145728),  region_resident = true,  region_backing = zeros(), region_generation = zeros() };
  veda_current_region   = zeros();       // region 0 is the running domain
  veda_current_odt_base = to_bits(56, 0); // its ODT base
  // 0x0001 was a valid 16-bit literal before this pass's widening; now
  // that odt_write takes bits(23), the literal must be built explicitly
  // (a bare hex literal is sized by its digit count, 4 hex digits = 16
  // bits, which no longer matches) -- same to_bits(width, value) pattern
  // already used in this codebase (veda_types.sail's vcapno_to_vcapidx).
  odt_write(to_bits(44, 1), struct {
    valid      = true,
    Base       = 0x00000080010000,
    Length     = 0x0000000040,
    Perms      = 0x100C,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,   // DESIGN_02: seeded objects are present in memory
  });
  // Milestone V-B addition: a second seeded object, deliberately *without*
  // Permit_NMC_Compute (Perms = 0x000C, Load+Store only), so a real
  // negative-control test can confirm NMC_ADD's own new permission gate
  // actually fires rather than assuming it does from the code alone.
  odt_write(to_bits(44, 2), struct {
    valid      = true,
    Base       = 0x00000080010100,
    Length     = 0x0000000040,
    Perms      = 0x000C,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,   // DESIGN_02: seeded objects are present in memory
  });
  // Milestone V-B addition: a third seeded object for use as a CSeal/
  // CUnseal type-authority capability -- Perms = 0x300 (Permit_Seal, bit
  // 8, + Permit_Unseal, bit 9, veda_types.sail's bit assignment), Length
  // = 0x10 so small in-range Offset values (used directly as otype) are
  // easy to construct by hand in a test program via OCA.
  odt_write(to_bits(44, 3), struct {
    valid      = true,
    Base       = 0x00000080010200,
    Length     = 0x0000000010,
    Perms      = 0x0300,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,   // DESIGN_02: seeded objects are present in memory
  });
  // Milestone V-B addition: a fourth seeded object identical to Object_ID
  // 3 except *without* Permit_Seal/Permit_Unseal, so a real negative test
  // can confirm CSeal/CUnseal's own authorization check actually fires.
  odt_write(to_bits(44, 4), struct {
    valid      = true,
    Base       = 0x00000080010300,
    Length     = 0x0000000010,
    Perms      = 0x0000,
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,   // DESIGN_02: seeded objects are present in memory
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
  odt_write(to_bits(44, 5), struct {
    valid      = true,
    Base       = 0x00000080010400,
    Length     = 0x0000000010,
    Perms      = 0x000C,
    generation = zeros(),
    owner_hart = 0x63, // 99 decimal -- a real, distinct, non-zero "other hart"
    retired    = false,
    // DESIGN_02: resident, so the wrong-owner fixture keeps reporting
    // OWNER_VIOLATION (0x06). A non-resident value here would be
    // indistinguishable in the test but wrong in meaning -- this object is
    // present in memory, it simply belongs to another hart.
    resident   = true,
  });
  // ── DESIGN_02 residency fixtures ────────────────────────────────────
  // Object_ID 600: an object that EXISTS (valid, sane Base/Length/Perms)
  // but whose contents are NOT in memory. Reset-seeded for the same reason
  // the region-2 capabilities are: a non-resident object cannot be reached
  // at runtime, because Populate is precisely the instruction that
  // ESTABLISHES residency -- so no instruction sequence can produce one.
  // That is the mechanism working, not a test inconvenience. This models
  // the real state after a pager has evicted an object's contents.
  //
  // 600 chosen after grepping the whole corpus for every Object_ID literal.
  // Deliberately NOT a low id: 6 is vc_bind_notfound_neg.S's never-populated
  // fixture, and seeding it would flip that test's expected OBJECT_NOT_FOUND
  // (0x05) into a residency fault -- the exact ordering confusion this
  // increment is trying to keep straight.
  odt_write(to_bits(44, 600), struct {
    valid      = true,
    Base       = 0x00000080010500,
    Length     = 0x0000000040,
    Perms      = 0x000C, // Load|Store -- nothing about perms is at issue here
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = false,  // THE fixture: the object exists, but is paged out
  });
  // Object_ID 611: the PAGE-OUT saturation fixture (DESIGN_02 increment 2).
  // Seeded ONE step below the 24-bit ceiling, so a single page-out reaches
  // 0xFFFFFF legitimately and the SECOND one lands exactly on the boundary
  // where the generation bump would become a silent no-op. Same
  // near-boundary injection technique the retirement fixture (Object_ID 55)
  // already uses, and for the same reason: driving 2^24 real increments is
  // not a test, and lowering the threshold for testing would leave the
  // shipping boundary arithmetic unexercised.
  //
  // Live and RESIDENT, unlike 600 -- this fixture is about the generation
  // ceiling, not about residency, and it must be page-out-able once.
  odt_write(to_bits(44, 611), struct {
    valid      = true,
    Base       = 0x00000080010600,
    Length     = 0x0000000100,
    Perms      = 0x000C, // Load|Store
    generation = 0xFFFFFE,
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,
  });
  // Object_ID 614: the GENERATION-PRESERVATION fixture. Seeded TWO steps
  // below the ceiling, deliberately not one.
  //
  // Why two and not one: at 0xFFFFFE a page-in that wrongly BUMPED
  // generation would saturate to 0xFFFFFF, which is indistinguishable from
  // correctly preserving 0xFFFFFF. The mutation hides in the saturation. At
  // 0xFFFFFD the two behaviours separate cleanly and become countable:
  //   preserving  -- FD->FE, FE->FF, then refused  = TWO page-outs
  //   bumping     -- FD->FE, page-in bumps to FF   = ONE page-out
  // The count of successful page-outs before the saturation refusal is the
  // observable, which matters because `generation` itself is architecturally
  // unreadable -- there is no CGet for it by design.
  odt_write(to_bits(44, 614), struct {
    valid      = true,
    Base       = 0x00000080010700,
    Length     = 0x0000000100,
    Perms      = 0x000C,
    generation = 0xFFFFFD,
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,
  });
  // Object_ID 615: the OWNERSHIP-PRESERVATION fixture -- live, resident, and
  // owned by a DIFFERENT hart (0x63 = 99, the same stand-in the Milestone-12
  // wrong-owner seed uses, since a single-hart model cannot produce a second
  // real owner).
  //
  // It exists to prove hart ownership SURVIVES a paging cycle. Page-out is
  // gated on ODA authority, not on ownership, so a pager can legitimately
  // evict an object it does not own; if page-in then reset owner_hart to
  // unowned -- which is exactly what using Populate as page-in would do --
  // any hart could claim the object afterwards. That is object theft by
  // triggering a page fault, and it is invisible in a one-hart model unless
  // a fixture like this one makes the ownership observable through Bind's
  // own 0x06 refusal.
  odt_write(to_bits(44, 615), struct {
    valid      = true,
    Base       = 0x00000080010800,
    Length     = 0x0000000100,
    Perms      = 0x000C,
    generation = zeros(),
    owner_hart = 0x63,
    retired    = false,
    resident   = true,
  });
  // Phase 1 increment 4: a sixth seeded object whose generation counter is
  // placed ONE below the real 24-bit retirement threshold (0xFFFFFE, i.e.
  // 0xFFFFFF - 1). This is the direct-state-injection answer to "how do you
  // test a 16.7M-reuse threshold" -- looping 16.7M destroys is infeasible, so
  // the slot is seeded near the boundary and a test drives the genuine
  // saturate-then-retire transition at the TRUE width with two destroys:
  // Destroy #1 bumps 0xFFFFFE -> 0xFFFFFF (saturated, not yet retired),
  // Destroy #2 sees the counter already at max and retires the slot. This
  // exercises the real threshold arithmetic, not a reduced stand-in, using
  // the identical reset-scaffold technique every seed above already relies
  // on (none is populated by a real ODT-Populate instruction either).
  // Object_ID=55, clear of the 1-5 seeds and the tests' own 50/51/60.
  odt_write(to_bits(44, 55), struct {
    valid      = true,
    Base       = 0x00000080010500,
    Length     = 0x0000000008,
    Perms      = 0x0004, // Permit_Load
    generation = 0xFFFFFE,
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,   // DESIGN_02: seeded objects are present in memory
  });
  // DESIGN_08 Sail experiment -- two cross-region seeds.
  // (A) region=1, local=1: Object_ID = (1 << 24) | 1. Its region is RESIDENT
  // (RT[1]), so it binds normally, but it is a DIFFERENT object than region-0
  // local-1 (Object_ID 1, Base 0x...010000 above -- unowned/bindable, unlike
  // Object_ID 5 which is the wrong-owner seed) -- given a distinct Base
  // 0x...020000 so a test can prove {region=1,local=1} and {region=0,local=1}
  // resolve to different objects (global uniqueness).
  odt_write(to_bits(44, 16777217) /* (1 << 24) | 1 = region 1, local 1 */, struct {
    valid      = true,
    Base       = 0x00000080020000,
    Length     = 0x0000000008,
    Perms      = 0x0004, // Permit_Load
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,   // DESIGN_02: seeded objects are present in memory
  });
  // (B) region=2, local=7: Object_ID = (2 << 24) | 7. Region 2 is NON-RESIDENT
  // (RT[2].region_resident=false), so the object exists in the modeled backing
  // but any Object-Bind of it must raise an explicit REGION_FAULT rather than
  // silently resolving -- the cache-less / explicit-fault invariant.
  odt_write(to_bits(44, 33554439) /* (2 << 24) | 7 = region 2, local 7 */, struct {
    valid      = true,
    Base       = 0x00000080030000,
    Length     = 0x0000000008,
    Perms      = 0x0004, // Permit_Load
    generation = zeros(),
    owner_hart = VEDA_OWNER_UNOWNED,
    retired    = false,
    resident   = true,   // DESIGN_02: seeded objects are present in memory
  });
  // ── R10 test scaffold: three CRF seeds naming region 2 ──────────────
  // A region-2 capability CANNOT be obtained at runtime, and that is the
  // mechanism working, not a test inconvenience: Bind is residency-gated,
  // so a paged-out domain's objects cannot be re-bound -- but capabilities
  // MINTED WHILE THE REGION WAS RESIDENT can still be sitting in registers
  // when it pages out. Residency is dynamic in the real design; these
  // seeds model exactly that legal state (the same direct state-injection
  // technique the wrong-owner and near-retirement seeds above already
  // use, because a single-hart test environment has no other way to reach
  // it). They exist so the R10 negative tests can prove that OCInvoke and
  // OCReturn REFUSE such a capability with an explicit REGION_FAULT
  // rather than entering a domain whose table is paged out.
  //
  // c10 = sealed region-2 CODE (Perms Execute|Invoke = 0x0402), c11 =
  // sealed region-2 DATA (Invoke only = 0x0400, deliberately non-exec),
  // matching otype 0x0042 -- together they pass all nine of OCInvoke's
  // capability checks, so the FIRST failure is the region gate, which is
  // precisely what the test must isolate. c13 = region-2 SENTRY (otype
  // 0xFFFE, Execute) for the OCReturn side. Object_IDs (2<<24)|8, |9, |10
  // -- distinct from seed (B)'s |7; none needs an ODT entry, because the
  // gate fires before any lookup (and neither crossing reads the ODT at
  // all). No existing test reads c10/c11/c13 before writing it
  // (grep-verified before choosing, and re-proven by the full-corpus
  // regression run).
  wC(Vcapno(10), struct {
    Object_ID  = to_bits(44, 33554440), // (2 << 24) | 8
    Base       = 0x00000080030000,
    Length     = 0x0000000040,
    Offset     = zeros(),
    Perms      = 0x0402, // Execute | Invoke
    otype      = 0x0042,
    generation = zeros(),
    flags      = zeros(),
  });
  wCTag(Vcapno(10), true);
  wC(Vcapno(11), struct {
    Object_ID  = to_bits(44, 33554441), // (2 << 24) | 9
    Base       = 0x00000080030000,
    Length     = 0x0000000040,
    Offset     = zeros(),
    Perms      = 0x0400, // Invoke only, non-executable
    otype      = 0x0042,
    generation = zeros(),
    flags      = zeros(),
  });
  wCTag(Vcapno(11), true);
  wC(Vcapno(13), struct {
    Object_ID  = to_bits(44, 33554442), // (2 << 24) | 10
    Base       = 0x00000080030000,
    Length     = 0x0000000040,
    Offset     = zeros(),
    Perms      = 0x0002, // Execute
    otype      = VEDA_OTYPE_SENTRY,
    generation = zeros(),
    flags      = zeros(),
  });
  wCTag(Vcapno(13), true);
  // c14 = region-3 SENTRY, the rt_valid-gate fixture (RT[3] is
  // {valid=false, resident=true}). OCReturn through it must REGION_FAULT
  // BECAUSE rt_valid is false, even though resident is true -- the sole
  // test that pins the fail-closed rt_valid conjunct. Object_ID (3<<24)|1.
  wC(Vcapno(14), struct {
    Object_ID  = to_bits(44, 50331649), // (3 << 24) | 1
    Base       = 0x00000080040000,
    Length     = 0x0000000040,
    Offset     = zeros(),
    Perms      = 0x0002, // Execute
    otype      = VEDA_OTYPE_SENTRY,
    generation = zeros(),
    flags      = zeros(),
  });
  wCTag(Vcapno(14), true);
  // ── DESIGN_02 residency fixture: a capability held across an eviction ──
  // c12 names Object_ID 600, which is seeded valid with generation 0 but
  // resident = false. This is the ONLY way to reach the dereference-side
  // residency gate: no instruction sequence can produce such a capability,
  // because Bind is residency-gated and Populate is precisely what
  // establishes residency. That is the mechanism working, not a test
  // inconvenience -- and it is exactly the legal, reachable state of a
  // capability minted while an object was resident and still held after a
  // pager evicted its contents.
  //
  // Deliberately well-formed in EVERY other respect -- tagged, unsealed,
  // generation matching the entry, Load|Store permitted, Length covering an
  // in-bounds access -- so it passes all five earlier checks in
  // veda_check_access and residency is the FIRST and ONLY thing that can
  // stop it. A fixture that failed an earlier check would prove nothing
  // about this gate.
  //
  // c12 chosen after grepping the corpus: its every read is preceded by a
  // write on the immediately-previous line, so seeding it disturbs nothing.
  wC(Vcapno(12), struct {
    Object_ID  = to_bits(44, 600),
    Base       = 0x00000080010500,  // matches Object_ID 600's seeded Base
    Length     = 0x0000000040,
    Offset     = zeros(),
    Perms      = 0x000C,            // Load|Store
    otype      = UNSEALED_OTYPE,
    generation = zeros(),           // matches the entry -- no staleness
    flags      = zeros(),
  });
  wCTag(Vcapno(12), true)
}
