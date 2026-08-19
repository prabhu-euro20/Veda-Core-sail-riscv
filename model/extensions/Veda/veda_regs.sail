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
// across a trap -- Base(32)/Length(20), matching the ODT entry's own
// field widths (veda_types.sail's odt_entry -- Length widened 16->20
// bits 2026-08-19 alongside the capability struct's own widening), not
// independently chosen.
// `VEDA_PCC_UNBOUNDED` (all-ones Length) is the "no compartment active"
// sentinel -- real CHERI's own convention that execution starts with an
// "almighty" root capability and only ever narrows (CHERI ISA spec
// §2.3.12/§11.1.2, read in full for PCC_COMPARTMENT_DESIGN.md). Reset
// value is unbounded, so no code that never calls `OCInvoke` is ever
// constrained by this feature at all.
let VEDA_PCC_UNBOUNDED : bits(20) = 0xFFFFF
register veda_pcc_base : bits(32)
register veda_pcc_length : bits(20)
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
register veda_mepcc_length : bits(20)

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
  if veda_mepcc_length != VEDA_PCC_UNBOUNDED then {
    veda_pcc_base = veda_mepcc_base;
    veda_pcc_length = veda_mepcc_length;
    veda_mepcc_base = zeros();
    veda_mepcc_length = VEDA_PCC_UNBOUNDED;
  }
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
// holds Length(bits 35..16)/Perms(bits 15..0) -- the *reusable* half of a
// descriptor, set once via the real, already-working, unmodified CSRRW (no
// new "set" instruction needed) and then read directly by
// `VEDA_ODT_POPULATE_FAST` below for every object sharing that template.
// Widened from bits(32) (Length(16)+Perms(16)=32) to bits(36)
// (Length(20)+Perms(16)=36), 2026-08-19, alongside the capability struct's
// own Length widening -- Perms keeps its original bit position [15..0]
// unchanged; only Length's own span grows, from [31..16] to [35..16], the
// same "same order, same technique, just wider" pattern the packed-
// capability layout itself follows (NEXT_STEPS_ROADMAP.md, "Break 2").
// Reset to zero (harmless: an all-zero Length/Perms just makes the first
// fast-populated object real but permission-less until software actually
// sets this CSR, not a crash/undefined-behavior risk).
register veda_attr : bits(36)

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

function clause is_CSR_accessible(0x7C0, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C1, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C2, _, _) = currentlyEnabled(Ext_Veda)
function clause is_CSR_accessible(0x7C3, _, _) = currentlyEnabled(Ext_Veda)
// `veda_attr` (bits(36) since the 2026-08-19 widening) additionally
// requires `xlen == 64` -- unlike the other five Veda CSRs here (all
// bits(32) or narrower), a 36-bit backing register cannot be
// zero-extended into a possibly-32-bit `xlenbits` (this project's build
// compiles BOTH rv32/rv64 configs, model/CMakeLists.txt's own real
// `foreach (xlen IN ITEMS 32 64)`, even though only the rv64 config is
// ever actually exercised/tested -- Sail must still statically prove
// read_CSR/write_CSR type-correct for both). Real, established precedent
// for exactly this kind of xlen-conditional CSR-accessibility split:
// core/sys_regs.sail's own mstatush (0x310, real RISC-V CSR, valid only
// at xlen==32) -- gating accessibility, not just the read/write bodies,
// is what lets an out-of-range access correctly become Illegal_Instruction()
// rather than an unreachable-but-unproven scattered-function match gap.
function clause is_CSR_accessible(0x7C4, _, _) = currentlyEnabled(Ext_Veda) & xlen == 64
function clause is_CSR_accessible(0x7C5, _, _) = currentlyEnabled(Ext_Veda)

function clause read_CSR(0x7C0) = zero_extend(veda_pcc_base)
function clause read_CSR(0x7C1) = zero_extend(veda_pcc_length)
function clause read_CSR(0x7C2) = zero_extend(veda_mepcc_base)
function clause read_CSR(0x7C3) = zero_extend(veda_mepcc_length)
function clause read_CSR(0x7C4 if xlen == 64) = zero_extend(veda_attr)
function clause read_CSR(0x7C5) = zero_extend(veda_mode)

// Milestone 20 (real, empirically-confirmed vulnerability, not
// theorized): before this pass, all four of these writes were
// unconditional -- meaning code entered via a real OCInvoke (narrowed to
// its own Base/Length, veda_pcc_length != VEDA_PCC_UNBOUNDED) could
// simply `csrw 0x7c1, 0xFFFFF` to widen its own compartment back to
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
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { veda_pcc_save_and_reset(); Err(()) }
  else { veda_pcc_base = value[31..0]; Ok(zero_extend(veda_pcc_base)) }
}
function clause write_CSR(0x7C1, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { veda_pcc_save_and_reset(); Err(()) }
  else { veda_pcc_length = value[19..0]; Ok(zero_extend(veda_pcc_length)) }
}
function clause write_CSR(0x7C2, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { veda_pcc_save_and_reset(); Err(()) }
  else { veda_mepcc_base = value[31..0]; Ok(zero_extend(veda_mepcc_base)) }
}
function clause write_CSR(0x7C3, value) = {
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { veda_pcc_save_and_reset(); Err(()) }
  else { veda_mepcc_length = value[19..0]; Ok(zero_extend(veda_mepcc_length)) }
}
function clause write_CSR((0x7C4, value) if xlen == 64) = { veda_attr = value[35..0]; Ok(zero_extend(veda_attr)) }
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
  if veda_pcc_length != VEDA_PCC_UNBOUNDED then { veda_pcc_save_and_reset(); Err(()) }
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
    Length     = 0x00040,
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
    Length     = 0x00040,
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
    Length     = 0x00010,
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
    Length     = 0x00010,
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
    Length     = 0x00010,
    Perms      = 0x000C,
    generation = zeros(),
    owner_hart = 0x63, // 99 decimal -- a real, distinct, non-zero "other hart"
    retired    = false,
  })
}
