# MIGRATION-TOOLS: moving translated text onto the disc

**TL;DR:** Current routes (2026-09-30 / 10-01): registry entries -> `tools/migrate_drafted_2026_09_30.py` (`--ids` for a subset); strings not in the registry and reached through pointer tables -> `tools/migrate_unregistered_2026_09_30.py --allow-file` (field-exact); strings reached only by lui/addiu -> add registry entries with `tools/merge_registry_additions_2026_09_30.py --additions X.json --write`, then `migrate_drafted --ids`. `$gp`-relative single-instruction references -> `tools/relocate_gp_relative.py`. All of them write to the stream blob (`skills/SENTINEL-STREAM.md`), import sizes from `tools/stream_capacity.py`, are dry-run by default, and use exact-scoped, reviewed waivers.

## Invariants

| Rule | Evidence |
|---|---|
| Prove every reader of a migrated field reaches a translator before migrating. | batches 5-14, 2026-09-30/10-01 |
| Waivers are exact-scoped (slot / site / pinned words + callee sha), each reviewed. | `tools/migrate_drafted_2026_09_30.py` |
| The ledger check accepts a row as *superseded* only when registry patched + pairs build landing_vma + blob == re-encoded en; any other mismatch FATALs. | same |
| Splice onto the live blob (`read_current_blob()`), never rebuild from ledger lists. | 2026-09-07 incident |
| `migrate_drafted --ids` writes a separate -ids-debug plan (it used to overwrite the full plan CSV). | 2026-09-30 |
| Strings memcpy'd with a fixed length cannot grow: hold or shorten (`REVIEW_HOLDS` in `tools/migrate_drafted_2026_09_30.py`). | title-award, 2026-09-30 |
| Phrase English around the JP argument order (`skills/CONTROL-CODES.md`, F050). | F050 |
| Check `free -h` before a real `--apply`; scratch copies go on the project's btrfs (reflink), not tmpfs. | 2026-09-09 |
| Fix tools: "does not fit slot / line budget" is a non-fatal FLAG (skip + report); integrity problems (stream neither OLD nor NEW) are FATAL before any write; re-create the `StreamEdit` per write. | 2026-10-01 name-consistency (`STRING-REGISTRY.md`) |
| Simulations must redirect `registry_io` via `rio.load.__defaults__`/`rio.save.__defaults__`, and snapshot the target entries first. | 2026-09-09 |

## Go reference-bound stream comparisons (2026-10-20)

An audit profile can add `observed_family` plus a fourth pinned source, `registry`.
Existing `auditStreams` then calls existing `references` and `inspect`: the family
and pair IDs must match numerically, every declared site must resolve validly to
one target, and the complete selected observed window must map from that target
to exactly its explicit file span. Check every site, not only the unique-target
count: one valid site must never hide a failed sibling. Include post-END tails
in the mapping check; a file-backed target point can lead into BSS. All binding
errors refuse without JSON. No target selection, ID fallback or new decoder.

The reference window and narrative/positional grammar stay explicit. Valid
binding can still produce a failed decode with unknown semantic comparisons;
raw bytes and differences remain known. Plain three-input audit behavior stays
unchanged. Registry joins the same final full-hash/identity checks. Bound observed
ELF and registry each cap at64MiB; reference windows still stream. Inline rename/
nickname fields have no END and already use the shared fixed-field planner:
never derive pointer words from their struct/offset metadata. The five-file
runnable example is `tools/go/examples/reference-bound-audit/profile.json`.
This proves stored source facts, not live readers or full canonical reconciliation.

## Go observed declared references (2026-10-20)

Use the separate `reference_observed` recipe with an explicitly supplied extracted
ELF and full-hash-pinned registry. A family selects declared sites; retain every
site ordinal, readable word and distinct target, including divergent targets.
The same pure geometry validation serves expected guards, append and reports;
strict observed word interpretation is shared by append and reports. Expected
guards still construct words without reading current instructions. Existing ELF
layout mapping owns full four-byte site spans and one-byte target classifications.
Unavailable words or invalid opcode/register pairs leave the target unknown.
Never replace it with the registry ID or a declared landing. A reconstructed
unmapped target remains a fact, not readable text or proof of a live reader.

This new report requires valid Unicode scalars throughout its JSON registry and
rejects typed-key aliases. Pointer arrays now reject unused struct coordinates
also in append; none of the 3,868 frozen canonical array entries had them.
Legacy advisory reports retain their output and input policies. Full source,
registry and profile identities are rechecked before report output. The bounded
accepted sizes are not a hostile-allocation sandbox. Compare explicit reviewed
stream windows with the existing paired audit rather than adding a decoder here.
See `tools/go/evidence/observed-reference-proof.json` for scope and limitations.

## Go paired stream audits (2026-10-20)

Use `tools/go --stream-audit-profile` for two explicitly selected file windows.
One profile pins both regular sources plus glyphmap by size/hash; ID-keyed pairs
choose narrative or positional grammar explicitly. Identical bytes can be valid
in both with different tokens. Reuse `controls`; never retry styles until one
matches. Compare through-END bytes separately from complete-span tails, glyph
words/text, positioned controls, control sequence, decoded argument words and
opaque payloads. Payload lookalikes are not independent arguments or END markers.
Failed decodes leave semantic comparison unknown, not equal or unequal.

Existing registry JSON ambiguity/Unicode checking is now shared `checkJSON`.
Profile-only closed typed-key sets reject ASCII and Unicode case-fold aliases
before Go's typed decoder; dynamic ID/glyph keys and registry opaque metadata
retain their contracts. Sources are fully streamed through SHA-256 and rechecked
before output. No apply/output path exists. This does not resolve live references,
construct canonical English, prove runtime argument roles or replace native fit.
The runnable example and exact limits are in `tools/go/README.md`; native JP-source
bytes must not be presented as sentinel translated-content verification.

## Go declared reference guards (2026-10-20)

`tools/go` extends existing `pointer_check` to explicit struct fields and strict
LUI/ADDIU pairs. Default target is the registry ID; `registry_landing` checks its
declared sentinel landing. Full opcodes/registers and signed-low carry are checked,
not only numeric target reconstruction. Code guards use the existing same-byte
`guarded_words` representation; the table still refuses every apply. Mixed shapes,
inconsistent struct coordinates, duplicated/shared physical words and unsupported
forms refuse. Old data-only physical scope hashes remain unchanged. This checks
recorded sites without reading payload text or proving liveness, exhaustive
references or landing ownership. See `tools/go/README.md` and the source-bound
`tools/go/recipes/reports/code-references.json` example.

## Go source inspection (2026-10-17)

The isolated [Go tools](../tools/go/README.md) now share a source decoder and
registry traversal for `registry_markup` metadata and the read-only `text_shapes`
report. Select the separate pinned recipe; the combined report emits both shape
and cluster JSON summaries on stdout and refuses `--apply`. Its current real-input
report excludes all three drafted rows as multi-site; synthetic full-report
comparisons establish decoded behavior. Report structure does not prove layout,
field capacity, argument semantics or gameplay.

When extending this path, validate the complete address `base + ID - delta` before
unsigned subtraction: `ID < delta` alone can discard a valid positive offset.
Keep source-order examples, source decoding and strict patch validation distinct,
and count opaque parameter payload words by glyph-key membership, including known
empty values. Highlight clean-pair reporting uses greedy sliding pairs; metadata
readiness has a different alternating-pair rule. Reuse the existing scan and input
checks rather than adding another decoder or one handler per dated script.

## Procedure

**Overnight 2026-09-30 -> 10-01 lessons (batches 5-14, applied and probe-verified on shipping, 0 TLB each run):**
- *Unregistered strings, pointer tables:* tools/migrate_unregistered_2026_09_30.py with a field-exact `--allow-file`. Prove every reader of the field reaches a translator; check every vanilla u32 equal to a string address is an allowed field. Getter 0x282360 (kinds 7/8 +8/+0xc, kind 0 +0x20, magic +0x18) has 21 callers, all translating. Item names use getter 0x2821d0.
- *Unregistered strings referenced only by lui/addiu:* add registry entries first (tools/merge_registry_additions_2026_09_30.py --additions X.json --write; it refuses duplicate ids and backs up the registry), then migrate_drafted --ids. Batches 12 and 14 used this route.
1. Dry run; read the plan CSV; check holds and waivers.
2. 2 independent reviewers.
3. Snapshot (`tools/backup_iso.py`), `--apply`, idempotent re-run.
4. `tools/build_change_ledger.py` + `tools/reconcile.py`; frozen live probe (`skills/VERIFICATION.md`).

## Reference: migrate_drafted waivers and ledger check
**Overnight 2026-09-30 -> 10-01 lessons (batches 5-14, applied and probe-verified on shipping, 0 TLB each run):**
- *migrate_drafted waivers (all exact-scoped, all reviewed):*
  - VERIFIED_FAR_HEADS, VERIFIED_PTRS and VERIFIED_IMMS (slot-level);
  - POS_OVERRIDES: reviewed pen-x/pen-y moves, compared against the moved JP;
  - SHIP facts: byte-verified, fail closed (0x2f9530 strcat, 0x349980 PARAM, NAMEPLATE_STUB 0x2f1ab0 = j 0x399c44);
  - SHIP_LUI_MOVE and BENIGN_LUI_USE (the apply-time site check honours it too);
  - FALSE_REFS: packed u16 number pairs that happen to equal a text vma.
  The ledger check accepts a row as *superseded* only when registry patched + pairs build landing_vma + blob == re-encoded en. Any other mismatch FATALs.
- *Registry id off by the pad words:* several JP 'ids' sit 6-10 bytes before the real string that the code builds (0x534c76 -> 0x534c80, 0x534cba -> code builds 0x534cc0, 0x47e262 -> 0x47e2c0). Always check what the lui/addiu actually builds.

## Gotchas

- **A short entry's own decoded `END` can be a false positive belonging to the NEXT entry's bytes - "capacity = distance to own END" is unsafe without also bounding against the nearest KNOWN following registry entry (found 2026-09-05, direct-patch pass)**: some pools (confirmed for `system_vocabulary`/`vocab-weapon-names`, e.g. `0x533b2a` "Poison Palm" / `0x533b36` "Snake Rod", exactly 12 bytes apart) are laid out as fixed-stride tables where a short JP entry's real content ends well before any `0xF800`-looking word - `dialog_codec.decode_structured()` happily keeps scanning past the true boundary, through the NEXT entry's own bytes, and can find a coincidental 16-bit value that looks like `END`. A capacity computation that trusts this false boundary will compute room for a write that's actually too long, and applying it will silently clobber the start of the neighboring entry's pristine content. First `--apply` of `tools/patch_maximal_coverage_exploratory.py` did exactly this (1,331 "successful" writes, caught only by a post-write verification sample decoding worse than expected). Fix: bound every generic-path capacity computation at `min(own_decoded_END_offset, distance_to_the_nearest_FOLLOWING_registry_entry's_own_VMA)` using a sorted list of ALL registry VMAs (bisect) - regardless of whether that next entry is itself a patch candidate. Dropped the safe write count from 1,331 to 439 (true number); re-verified zero overlapping write regions across the corrected set. Apply this bound to ANY future tool that computes "how much room does entry X have" from a decode-scan alone, not just to entries adjacent within the same known family.
- **Re-migration guard: a hardcoded 2-value hex check does not generalize - reconstruct the address instead (fixed 2026-09-05)** - an exploratory bulk-migration script's first version detected "this entry was already sentinel-migrated by an earlier run" by matching two literal known-good byte strings from a single prior proof-of-concept entry. The real, general fix: reconstruct whatever VMA the CURRENT on-disk bytes actually encode (lui+addiu hi/lo reassembly for code_immediate; direct u32 read for pointer_array) and check membership in the sentinel range generally. Verified necessary at scale: a later run's allocator assigned 44 entries to DIFFERENT sentinel offsets than an earlier run had given them, all correctly caught and re-migrated only by the general check.
- **A batch-wide hazard check needs to actually run on the WHOLE batch, or it's just documentation** - the shared-lui-instruction hazard (two registry entries repointed off one shared `lui`, only one can win the upper-16-bits) was logged as a known risk but the allocator had no code enforcing it; a later bulk run happened to avoid it (2 real shared-lui groups, both landed with matching hi16, by luck of ID-sorted allocation order, not by design). Added a real post-allocation check (group every code_immediate ref_site by `lui_vma` across the full batch, hard-fail on any hi16 mismatch) - turns "we know this could happen" into something that actually stops a bad batch rather than relying on allocation order staying lucky forever.
- **An exploratory migration script's "idempotent re-run" only covers re-running the SAME script once, not re-running it again after it already partially succeeded (2026-09-05, remaining-backlog 2nd pass)** - `migrate_remaining_backlog_exploratory.py` checks candidates against `existing_ids` sourced from the ORIGINAL 644-entry ledger only, never against its own prior output ledger. Re-running it with a different candidate order against a working ISO that already had its own first-run results baked in would have tried to re-migrate already-migrated entries at brand-new sentinel offsets - the cursor/space accounting has no idea those bytes are already spoken for, so this both wastes space and risks two conflicting ledger rows for the same id. Avoided by rebuilding the working ISO fresh from the pre-this-tool base before re-running with new logic, rather than mutating the already-migrated copy in place. Any tool whose own idempotency check only looks one layer back (the base state, not "have I myself already run against this exact working file") needs this treated as a real gap, not assumed safe to iterate on.
- **A relocation helper's "the stored pointer always equals the entry's own `id`" assumption is not universal, and it only gets tested once you reach a pool where it's false (2026-09-05, remaining-backlog 2nd pass)** - `relocate_to_sentinel.py`'s `build_edits_pointer_array()`/`build_edits_code_immediate()` both compute their expected "old" bytes purely from the registry entry's own `id`, with no verification that the CURRENTLY-STORED value at the ref_site actually matches it. This held for every pool checked before tonight (541/541 monster+item, 87/87 ybs_script) but is false for the majority (534/748, 71%) of `system_vocabulary`'s `pointer_array` entries - the stored pointer sits a small, always-positive, always-even number of bytes (2-14, i.e. 1-7 glyph-words) AFTER the registered `id`, a pattern consistent with variable-length zero/alignment padding between the previous string's `END` and this string's true content start, with `id` recorded at the first byte after that `END` rather than at the pointer's real target (root cause not fully confirmed, but the delta pattern is a strong, well-characterized lead for later work). The existing expected-old-bytes write-time safety net caught every one of these as a clean refusal (0 corruption) rather than a silent bad write - but only AFTER a disc-blob rebuild had already assumed they'd succeed, wasting real sentinel-range space. Lesson: when reaching a NEW pool for the first time with an existing relocation helper, add a pre-check (verify the ref_site's current stored value actually equals the entry's own `id`) BEFORE accepting it as a candidate, not just rely on the write-time refusal to catch it after the fact.
- **A "bound the write against a decoded END offset" safety fix can be silently inert if the offset is absolute instead of relative - and the fallback for "no neighbor" case matters just as much as the normal case (2026-09-05, maximal-coverage direct-patch pass)** - `patch_maximal_coverage_exploratory.py`'s first fix for a real neighbor-clobbering bug computed `cap = t["off"] + 2` where `t["off"]` is `decode_structured()`'s ABSOLUTE byte offset into the whole ELF buffer (millions), not relative to the entry's own start - so `min(cap, next_vma_cap)` always picked the (correct, small) `next_vma_cap` term and the "own decoded end" bound was permanently dead code. This shipped, was reviewed as "fixed," and still let 32 of 439 writes overwrite real unregistered data (pointer tables, index tables) sitting in gaps the fix wrongly treated as free. Worse, the ONE entry with no "next" neighbor at all got the raw unbounded absolute value with no safety net whatsoever - the single most dangerous case had the weakest check. Two lessons: (1) when computing a capacity/bound from a decoder's own offset field, always double check whether that field is absolute-into-the-buffer or relative-to-the-slice you handed it - the two look identical in a spot-check that happens to also have a tight secondary bound (here, `next_vma_cap`) doing the real work unnoticed; (2) explicitly test the "no neighbor exists" edge case of any bounding logic - it's exactly where a silently-broken primary bound has nothing to fall back on.
- **`$gp`-relative single-instruction references are a distinct ref-site shape neither `relocate_code_immediate.py` nor `relocate_to_sentinel.py` can represent - RESOLVED 2026-09-07 via a new dedicated tool** - a bare `addiu $reg,$gp,imm16` (no preceding `lui`, since `$gp` is a fixed runtime constant, not a per-reference value) has no `lui` half to repoint; `relocate_code_immediate.py`'s `ref_sites` schema and `find_eligible()`/`build_edits()` hard-require a `lui_vma`+`addiu_vma` pair and assert opcodes accordingly. Found blocking ~9 registry entries (5 header-banner labels + 4 bonus finds) during the 2026-09-07 owner-manual-playthrough follow-up (`docs/planning-log/2026-09-07-owner-manual-playthrough-investigation-pass1.md` part 2). **`$gp` is NOT a fixed constant to hardcode across sessions - re-derive it live from the ELF's own `SHT_MIPS_REGINFO` section** (this session: `0x536bf0`) rather than assuming a remembered value. Widening to a `lui`+`addiu` PAIR in place is NOT generally possible here: fresh disassembly of every real gp-relative site found showed each sits either directly in a `jal`'s mandatory delay slot (no room for a 2nd instruction without corrupting that call) or immediately precedes another real `jal` with zero slack - would need a full SUBST-hook-style trampoline (save/restore live registers, a fresh landing zone, 2 adversarial reviews) PER SITE, the same effort class as the controller/personality SUBST-hook work, not a quick fix. **The mechanism actually implemented** (`tools/relocate_gp_relative.py`): since a plain `addiu $reg,$gp,imm16` can address ANY VMA within `$gp +/- 32767` (imm16 is signed), repoint IN PLACE to a hand-curated, individually `zone_safety.py`-full-battery-verified zero-run inside that +/-32K window - same instruction, same register, same delay-slot position, ZERO instruction-count change, none of the widen-in-place risks above. The reachable window this session (`[0x52ebf0, 0x53ebef]`) sits entirely inside the ELF's original single LOAD segment, so content lands via the STANDARD `ISO_OFF=0x9F800`/`DELTA=0xFFF80` formula, same as any other in-place ELF-mapped write - the sentinel disc-streaming mechanism is not involved. `VERIFIED_SAFE_ZONES` in that tool is deliberately a small, hand-curated table (not an auto-discovered pool) - adding a new zone needs the same manual battery + disproof rigor as the landing-zone search workflow above, not just a bigger `--min`. A companion tool, `tools/backfill_gp_relative_refs_2026-09-07.py`, closes the matching `ref_type: unknown` registry-metadata gap (pure bookkeeping, zero ISO bytes) for entries this shape was found for.
**A real, non-hypothetical memory-pressure hazard confirmed 2026-09-09 during the `vocab-shop-verbs-misc` `--apply`: this project's migration-script convention of holding multiple full-ISO (~4 GiB each) byte buffers in memory simultaneously (`data`, `working_bytes`, `mod`, `mod_check`, plus `mod2`/`mod_check2` whenever a sector-count bump triggers the loader-trigger-hook-rebuild path - up to ~24 GiB of simultaneous full-ISO buffers) is a genuine OOM-kill risk on a system already under memory pressure, not just a theoretical inefficiency.** The `--apply` run was killed by the OS OOM killer partway through (system had only ~15 GiB available with 10 GiB already in swap BEFORE the script even started - pre-existing pressure, not caused by the script alone, but the script's own memory footprint is what tipped it over). Because Python's stdout is fully buffered when redirected to a file (not a TTY), the kill produced ZERO captured output, making the failure look far more mysterious than it was. **Recovery procedure, verified safe and repeatable**: (1) check `free -h` before assuming anything is wrong; (2) determine how far the apply got via FILE TIMESTAMPS, not guesswork - does the pre-write backup exist and predate the working ISO's own mtime (proves phase2+ started)? Does `patch_iso_stream_blob.read_current_blob()`'s sector count match the expected POST-apply value (proves phase3/5 completed)? Does the registry file's own mtime PREDATE the apply run entirely (proves `rio.save()` was never reached, i.e. the ISO write finished but the registry write-back didn't)? (3) Before writing anything further, independently re-verify EVERY entry the ledger claims to have migrated, fresh, against the CURRENT (possibly-already-migrated) working ISO - resolve each `ref_site`, confirm it lands on the ledger's assigned VMA, confirm the on-disc bytes at that VMA byte-exactly match the ledger's own `bytes_hex`; also diff the loader-trigger hook's stub tail (past the rebuilt zone) between the backup and current working ISO to confirm the rebuild didn't corrupt anything outside its own bounds. (4) Only once every entry independently re-verifies cleanly, run a SEPARATE, deliberately memory-light, read-only-except-for-the-registry recovery script to complete JUST the missing step (typically the final registry write-back) - never re-run the full original script blind, since re-doing the expensive full-ISO-buffer phases risks a second OOM kill for zero benefit (the ISO side is often already done). **Future migration scripts should check `free -h` before a real `--apply`** (not just before booting PCSX2, which this project already does) and treat low headroom as a reason to close unrelated memory-heavy applications first, not just proceed and hope. Full recovery worked example: `docs/planning-log/2026-09-09-vocab-shop-verbs-misc-migration.md`.
**A generalizable multi-site repoint-script bug found 2026-09-09 by 2 independent adversarial reviewers, BEFORE `--apply` — dispatch by SITE shape, never by the owning entry's single `ref_type`.** An entry can be "hybrid": primary `ref_type: pointer_array` (per the schema note above) whose `ref_sites` list ALSO contains `lui_vma`/`addiu_vma`-shaped (`code_immediate`) sites — 11 of 129 real-world entries in the 2026-09-09 board-event/battle-status batch were exactly this shape. A repoint loop that branches ONCE per entry (`if row["ref_type"] == "pointer_array": for site in ...: site["pointer_vma"]`) rather than once PER SITE (checking `"pointer_vma" in site` on each site individually) raises `KeyError` on the first `lui_vma`-only site of a hybrid entry — and since this bug lives in phase4 (the actual write phase), which a dry run structurally never reaches, it is invisible until a real `--apply` (the SAME class of gap the "Recurring gotcha" note below already documents for human-field writes — a dry run that never exercises phase4/6 can hide an entry-shape bug just as easily as a field-allowlist bug). Both reviewers independently reproduced the crash from real registry data before it was ever run for real. **Fix**: dispatch every site individually by which keys it actually carries, and widen any "shared lui_vma across this batch" pre-flight safety scan to check every site with a `lui_vma` key regardless of the owning entry's `ref_type` (a scan keyed off entry-level `ref_type` alone silently missed a real shared-lui pair between two `pointer_array`-typed hybrid entries in this same batch). **To verify a fix like this for real** (not just re-argue it), simulate a full `--apply` against a reflink-copied scratch ISO + scratch registry (`cp --reflink=auto` on a COW filesystem — btrfs confirmed working, near-instant, zero extra disk cost until blocks diverge) with the migration module's `WORKING_ISO`/`NEW_LEDGER_PATH`/`registry_io.load`/`registry_io.save` monkey-patched to the scratch copies — this is the concrete, repeatable version of the "simulate the registry-write phase against a `copy.deepcopy()`'d registry" advice already given below, now generalized to the ISO-write phase too. See `docs/planning-log/2026-09-09-board-event-battle-status-migration.md`.

**Gotcha on the reflink-scratch technique above, found 2026-09-09: the scratch copy MUST land on the project's own btrfs filesystem, not this project's usual scratchpad directory if that happens to be `/tmp`.** `cp --reflink=auto` silently falls back to a full physical copy (no error) when source and destination are on DIFFERENT filesystems — and in this session's environment, `/tmp` was `tmpfs` (RAM-backed), a different filesystem from `/home`'s btrfs where the project and its ~4GB ISOs live. A first attempt reflink-copying into the standard scratchpad path silently duplicated all 4GB into RAM instead of taking the COW path (confirmed via `df -T` on both paths). This is dangerous on its own merits — it directly stacks a ~4GB RAM allocation on top of the exact memory-pressure conditions that already caused a real OOM kill once this same night (see the OOM-recovery note above) — before a simulation script has even loaded its own multi-GB buffers. **Fix**: `df -T <path>` both the source ISO's directory and the intended scratch destination first: they must report the SAME device/filesystem type (btrfs, in this project) for `--reflink=auto` to actually take the COW path. A real reflink copy of this project's ~4.2GB ISO completes in well under 1 second; if a "reflink" copy takes several seconds or more, it silently wasn't one — abort and pick a same-filesystem destination (a dotfolder inside the project's own working directory is simplest) instead of trusting the scratchpad path blindly.

**A SECOND reflink-scratch gotcha, found 2026-09-09 (`item-village-event-messages2` pass), that caused a REAL accidental write to the live registry despite believing `registry_io` had been redirected to a scratch copy: reassigning `rio.REGISTRY_PATH` after import does NOT redirect `rio.load()`/`rio.save()`, because both are defined as `def load(path=REGISTRY_PATH):` / `def save(data, path=REGISTRY_PATH):` — Python evaluates a default parameter value ONCE, at function-definition time, and bakes it into the function object. Reassigning the module-level `REGISTRY_PATH` name afterward changes what the *name* points to, but the already-compiled function's default is a separate, frozen reference to the original path object; every no-arg `rio.load()`/`rio.save(reg)` call (which is how every migration script in this project actually calls them - never with an explicit `path=`) keeps hitting the REAL `registry/string-registry.json`, silently, with no error.** This was caught only because the entries this simulation "migrated" showed up with `status: patched` and sentinel `landing_vma` values in the real registry immediately after a scratch-ISO dry-run-turned-`--apply` simulation - values that pointed at content which only ever existed in the scratch ISO, never the real `modded-sentinel-bypass-fix.iso`, i.e. a self-inflicted, textbook registry write-back-gap-in-reverse (status claims patched, disc has nothing there). Recovered cleanly only because a pristine pre-run JSON snapshot of the exact 42 target entries happened to already exist from this same pass's own earlier read-only survey step - restored by id-keyed dict replacement, re-verified the whole registry's status histogram matched the pre-incident baseline exactly. The ISO side of the same simulation was NOT affected (`WORKING_ISO` is a plain module-level name the migration scripts read directly out of their own globals every time, not a function-default parameter, so reassigning `mod.WORKING_ISO` after import DOES correctly redirect every read/write) - this bug is specific to the registry_io no-arg convenience-default pattern. **Fix, for any future reflink-scratch registry simulation: do not reassign `registry_io.REGISTRY_PATH` and trust it. Instead reassign the frozen defaults directly - `rio.load.__defaults__ = (scratch_path,)` and `rio.save.__defaults__ = (scratch_path,)` - or replace the two names outright with wrapper closures that hardcode the scratch path, then verify by asserting `rio.load()` returns the scratch registry's own known-distinct content before trusting anything else the simulation does.** ALWAYS snapshot (a plain read-only JSON dump is enough) the exact target-entry set of any registry-touching script BEFORE running anything claiming to be a "simulation" or "dry run" of it - this project has now been saved by exactly this habit once already.

## History / batch log (2026-09-09 no_markup_yet and write-back sweeps; moved from STRING-REGISTRY.md 2026-10-01)

Point-in-time batch reports. Their lessons are summarised in the Invariants/Gotchas above and in `skills/STRING-REGISTRY.md`; use these for evidence and worked examples.

**Follow-up 2026-09-09 - first real `no_markup_yet` authoring batch found a NEW encoder blocker class: odd hl-like token counts.** `tools/migrate_battle_status_messages_2026-09-09.py` applied `derive_en_positional_markup()`/`encode_mixed_markup_stream()` to 18 `no_markup_yet`-tagged entries (`battle-status-messages-1/2/3`) that had ZERO existing markers - a real translator-authoring pass, not mechanical backfill. 15 migrated and live-PINE-verified 15/15 MATCH (2 independent fresh adversarial reviewers, both SAFE TO APPLY, one caught a real self-inflicted-agency meaning bug in a first draft before it shipped). **3 held back for a genuinely new reason**: their real JP byte stream has an ODD count of hl-like (colour-set/pen0-wrap) tokens (`0x476c30`/`0x476c60`: 5, a mid-stream orphan `0xb004` with no partner anywhere; `0x478e00`: 3, a leading never-closed `0xb004` plus a clean `0xe832`/`0xe864` pair) - `_check_hl_pairs_single_page()` unconditionally raises `EncodeError` on any odd count, regardless of wording, since `derive_en_positional_markup()` mandates a marker for every JP hl-like token 1:1 with no way to omit one. Not a translation gap - a genuine, narrow mechanism limitation, confirmed via real code execution and independently re-confirmed by both reviewers. Full detail: `docs/planning-log/2026-09-09-battle-status-messages-migration.md`, `docs/planning-log/OPEN-QUESTIONS-2026-09-08.md` section 3. Also confirmed: real JP decode can be RICHER than the registry's own simplified `jp` field implies (`0x479020`/`0x479050` decode to 4/5 icon tokens - 1 victim + 3/4 items - though their registered `jp` shows only 2/3 apparent blanks after control-code stripping) - always decode fresh, never trust the simplified `jp` field's blank COUNT as authoritative, only its general shape/intent. **All 15 newly-migrated entries immediately show as `reconcile.py` `patched_diverged` hard errors** - confirmed 100% cosmetic (byte-content-identical after stripping markup on both sides), the SAME already-documented write-back-gap/auto-wrap class below, just recurring for a NEW `patch_ref` prefix (`sentinel:battle_status_messages_2026-09-09`) that `reconcile.py`'s `is_phase3` relaxation doesn't cover (it only fires for `phase3-`-prefixed refs) - confirms this gap will keep recurring for every new non-`phase3-` migration pass until `reconcile.py`'s comparison logic is widened, not a one-off.

**Follow-up 2026-09-09 - second `no_markup_yet` batch, `village-chief-event` (39/39 migrated, 0 held back) - mechanism generalizes cleanly, single-marker entries are much cheaper than multi-value ones.** `tools/migrate_village_chief_event_2026-09-09.py` widened `derive_en_positional_markup()`/`encode_mixed_markup_stream()` to the largest remaining `no_markup_yet` chapter (39 of 276 entries, 3 event groups x 10 recurring personas). Unlike the battle-status-messages precedent, EVERY entry here has exactly ONE substitution point (a single hl-open/icon/hl-close triple, hl-like count always 2/even) - no odd-hl-count blocker, no multi-value order-preservation hazard anywhere in this bucket, making this a near-mechanical marker-insert pass rather than a full authoring pass. All 39 migrated and live-PINE-verified 39/39 MATCH (full census). 2 independent fresh Sonnet reviewers both returned SAFE WITH CHANGES NEEDED (not SAFE outright) - real findings, both classes worth generalizing: (1) **persona/dialect-voice regression risk when inserting a marker into a drafted line that used a NATURAL-LANGUAGE proxy for the missing value** - `0x482260` (a Southern/cowboy-dialect persona) had drafted en `"Care to donate somethin' toward our development?"`, where the apostrophe in "somethin'" was ITSELF doing double duty as both the dialect marker AND the value placeholder; replacing it with a plain marker + "gold" silently dropped the persona's dialect entirely. Fixed by re-adding an explicit dialect tag ("...development, y'all?"). **Lesson: when a drafted en's "blank" is disguised as an existing word/contraction rather than an obvious empty gap, check whether that word was carrying stylistic weight beyond just marking the substitution point.** (2) **A migration script's own docstring citing a review doc that doesn't exist yet is a real, catchable bug** - this script's first draft claimed "2 reviewers already signed off, see docs/planning-log/...md" before either review had happened or that doc existed, and that false claim would have been written verbatim into 39 registry `note` fields at `--apply`. Fixed by writing the real doc first and correcting the docstring/note text to describe the review that actually happened. **Lesson: never author a "reviewed and approved" citation before the review has actually occurred - write it as a TODO or omit it, then backfill once real.** Also independently reconfirmed (both reviewers, from different angles) that `0x8800` remains a genuinely polymorphic runtime-value slot project-wide (money here; a person's name at `0x459800`; an item at `0x459be0`) - the "gold amount" reading for this chapter's donation/stay-payment groups is a context-driven judgment call, not a general rule, though well-supported by this chapter's specific context (no plausible person/item reading fits "we need ___ for development") and independently corroborated by `board-event-ui-labels`'s own real-decoded streams (which use a DIFFERENT icon, `0x9000`, for "current gold total" bare, and `0x8800` for a gold delta like "collected X"/"cost X" - i.e. `0x8800`-as-money-delta already has precedent elsewhere in the project, not invented for this pass). `reconcile.py` hard-error count moved 225->264 (+39, spot-verified 100% the same already-documented cosmetic write-back-gap class, not new content bugs). Full detail: `docs/planning-log/2026-09-09-village-chief-event-migration.md`. **Not migrated this pass** (investigated, real decode captured, recommended as a dedicated follow-up): `board-event-ui-labels`'s 16-entry and `item-village-event-messages`'s 14-entry `no_markup_yet` subsets - both show multi-substitution-point shapes (2-9 hl/icon tokens per entry, at least one leading-prologue-position substitution) materially closer to battle-status-messages' difficulty than village-chief-event's single-marker simplicity.

**Follow-up 2026-09-09 - third `no_markup_yet` batch, `board-event-ui-labels` (16/16 migrated, 0 held back) - the batch both prior passes flagged as "materially harder" turned out to encode cleanly with zero mechanism blockers, but needed real multi-value order-preservation authoring.** `tools/migrate_board_event_ui_labels_2026-09-09.py` widened `derive_en_positional_markup()`/`encode_mixed_markup_stream()` to the 16-entry `no_markup_yet` subset of `board-event-ui-labels` (board-event notification/system messages: monster invasions, gold costs, theft, job change, item transmutation, bank deposit, blackmail letter - NOT the Settings/Controls UI-grid entries in the same chapter, a different sub-type already covered elsewhere in this doc). Unlike `village-chief-event`'s single-marker simplicity, every entry here has 2-14 hl-like/icon/param8 tokens with real relative-order constraints - closer to the `battle-status-messages` precedent's difficulty, as both prior passes predicted. All 16 migrated and live-PINE-verified 16/16 MATCH (full census). **Real, reusable finding: a `jp_prologue()`-classified LEADING hl/icon/param8 token is repositionable via `derive_en_positional_markup()` exactly like a mid-content one** - this was not obvious going in (the mechanism's OWN docstring talks about stripping the leading prologue run only to avoid double-emission, and a DIFFERENT, stricter sibling function `derive_en_prologue_markup()` exists specifically because a genuinely-leading substitution normally CANNOT be repositioned) - but confirmed via 2 real entries (`0x479fc0`'s leading bare `icon:0xa000`, `0x47c370`'s leading `hl:0xb003` wrapping real glyph text) that `derive_en_positional_markup()`'s own `jp_seq` is built from the FULL token stream regardless of prologue classification, so a translator's marker for that token can go anywhere in `en_text`, not just the front - only genuinely disqualifying CONTENT (a true pen0/setup token past the leading run) forces the stricter, non-repositionable prologue-echo tier. **Confirmed again (3rd/4th instance project-wide): the registry's own `midcontent_markup_shape.n_target_tokens` metadata undersells real byte-level substitution-point counts** - 2 entries needed real translator attention for this (`0x47bbe0`: tagged 4, real 9; `0x47c120`/`0x47c150`/`0x47c1f0`: tagged 2, real 3 each - thief AND victim AND item/amount, not just victim+item), and an adversarial reviewer's own exhaustive count found the SAME field mismatches real content in 11 of the 16 entries total (not safety-relevant - the migration mechanism never reads this field, only a fresh live decode does - but flagged as a real, standing metadata-staleness gap worth a future cleanup pass, not yet fixed). **A genuinely ambiguous byte shape, resolved safely rather than blocked**: 2 entries (`0x47bbe0`, `0x47c220`) contain two back-to-back occurrences of the SAME icon code with no separator/hl-wrap distinguishing them - the runtime argument-queue values behind each are unconfirmable from static bytes alone. Resolved generically (no invented conjunction for `0x47bbe0`; treated as one opaque compound label per side for `0x47c220`, matching an already-shipped identical shape at `0x478f20`/`battle-status-messages`) rather than guessing a specific reading - logged to `docs/planning-log/OPEN-QUESTIONS-2026-09-08.md` section 4 as a still-open item for a future live-PINE runtime-value capture, not blocking. 2 independent fresh Sonnet reviewers both returned SAFE TO APPLY outright (not "with changes needed" - a first for this mechanism's 3 real-world batches so far); the one real finding (an unsupported "!" before a ♪ glyph on `0x47c4b0`'s page 2, JP's real bytes carry no exclamation there) was cosmetic, non-structural, and fixed before `--apply`. **A real live-verify TOOLING bug, not a content bug**: the live-PINE verification script's first run used a PINE read window sized off "the entry that looked hardest" (`0x47c4b0`, 14 markers) rather than the actual largest BYTE size in the pass (`0x47a020`, 250 bytes) - undersized by 50 bytes, causing 1 `DECODE FAILED` (buffer too short to reach the stream's `END` token) on an otherwise-correct entry; fixed by widening the window and re-verifying the full batch fresh (16/16 on the re-run). **Lesson for any future live-verify script**: size the PINE read window off `max(len(bytes.fromhex(row["bytes_hex"])) for row in ledger["entries"])`, not off which entry subjectively seemed hardest to translate - marker COUNT and BYTE SIZE are not the same axis. Full detail: `docs/planning-log/2026-09-09-board-event-ui-labels-migration.md`. Registry `status != drafted` (done) count: 2430 -> 2446. `board-event-ui-labels` chapter's `no_markup_yet` backlog: 16 -> **0** (fully cleared; chapter now 29/90 patched, the remaining 61 drafted entries are outside this mechanism's scope - mostly the already-documented "true pen0 UI-grid"/"unclassified control-word" blocked classes plus ordinary not-yet-authored drafts). **Not migrated this pass** (light read-only recon only, terminology/tone precedent confirmed and ready for a future pass): `item-village-event-messages`'s 14-entry `no_markup_yet` subset - fresh-decoded and found structurally comparable to or simpler than this chapter (mostly 1-2 substitution points, a clean 4-entry "drained STAT from Y" family reusing shipped `Attack`/`Defense`/`Magic`/`Speed` stat names).

**Follow-up 2026-09-09: the cheap/safe fixes from the list above were actually applied** (not just recommended) during the overnight goal loop: (1) `build_change_ledger.py`'s `phase3_stream_markup()` now emits `{{PARAM:}}` for `icon`-kind tokens (kills 33 false divergences); (2) `decode_labels()` now skips the `0xE8xx` SET_SCALE control word instead of leaking it as literal text; (3) `decode_labels()`'s hardcoded `EN_S2_VMA` constant corrected `0x4554B8` -> `0x4DB790` (unblocks ledger regeneration, which was crashing); (4) the 3 drifted `landing_vma` entries (`0x4ef28c`/`0x4ef29a`/`0x4ef2a2`) corrected. A 5th, DIFFERENT bug was found and fixed in the same pass: `reconcile.py`'s `width_limit_risk`/`height_limit_risk` checks stripped `{{HL:}}`/`{{PARAM:}}` markup before counting visible chars, but never stripped settings-option's own `<0xNNNN>` notation — causing 11 false-positive warnings on every multi-choice settings-option entry (confirmed false via the real encoder, `encode_settings_stream()`, independently: 2-3 true rendered lines, matching the 2026-09-08 Help-box reword's intent exactly). Both files now re-run clean: `build_change_ledger.py` regenerates without crashing, `reconcile.py`'s warning count dropped 1156->1145 with the 209 pre-existing hard-errors unchanged (unrelated, not investigated this pass). NOT fixed this pass (deferred per the priority list above): the `dialog_codec.classify_word()` 0xB000 special-case, and the 137+32 write-back-gap/auto-wrap buckets.

**Follow-up 2026-09-09 - fourth `no_markup_yet` batch, `item-village-event-messages` (14/14 migrated, 0 held back) - the last of the 3 chapters flagged as "materially harder", and it fully confirmed the pattern.** `tools/migrate_item_village_event_messages_2026-09-09.py` widened `derive_en_positional_markup()`/`encode_mixed_markup_stream()` to the 14-entry `no_markup_yet` subset of `item-village-event-messages` (piggy bank, item-eating pest, paid transport, place-swap, 4x stat-drain + 1 failed-drain, 2x trap-count, village-chief seduction, transformation countdown, gather-everyone). All 14 migrated and live-PINE-verified 14/14 MATCH (full census). No odd-hl-count blocker, no hl-pair page-split, sector count unchanged (111->111, fit inside space already free - no loader-trigger hook rebuild needed, unlike the 2 prior passes that did need one). **The "registry undersells real content" gotcha is now confirmed in 100% of this chapter's 14 entries** (not just a few) - 5 by a FULL missing substitution point (the drafted `en`'s visible blank count was short by one whole role, e.g. `0x47c980`/`0x47cba0`/`0x47d660` each registered `n_target_tokens:1` but really have 2 - a subject/actor AND a separate target/victim the drafted wording didn't even render a gap for), the other 9 by one token each (an hl-wrapped literal-text run, e.g. "piggy bank"/"Attack", not separately tallied in the registered count). Worth treating this as the DEFAULT assumption for any future `no_markup_yet` chapter, not a per-chapter surprise: **always decode fresh from `iso/original/original.iso`, never trust `midcontent_markup_shape.n_target_tokens` as a ceiling on real substitution count.** **New reusable translator-authoring pattern confirmed**: when JP's real value order is drainer/actor -> victim/target -> a literal descriptive noun -> an amount (the stat-drain family here), a possessive construction ("X drained Y's STAT by N points.") preserves that exact order without an awkward passive - a cleaner solution than the passive-voice workaround the `battle-status-messages`/`board-event-ui-labels` precedents needed for similar shapes; worth trying possessive-construction first for any future actor->victim->descriptor->amount shape. **One judgment call, resolved with stronger evidence than the mechanism alone provides**: `0x47d3c0` (village-chief seduced by a "Queen") has a value directly abutting the literal glyphs for 女王様 (Queen) with NO particle/possessive between them (name+honorific direct compounding) - rendered "Queen {{PARAM:0xa000}}" (Western name-order); independently strengthened by both adversarial reviewers, one of whom found "Queen" is ALREADY the locked translation for 女王様 elsewhere in this project (`0x534692`, vocab-jobs, already `patched`) - when a judgment call involves a title/honorific, check whether this project has ALREADY locked a translation for that title elsewhere before treating the call as unconstrained. Logged to `docs/planning-log/OPEN-QUESTIONS-2026-09-08.md` section 5, not blocking. **A real process-hygiene bug, caught a 2nd time by the exact same class of finding**: this script's docstring (like `village-chief-event`'s before it) initially asserted "2 reviewers already signed off" and pointed to a review doc section that was still an empty placeholder when the first reviewer actually read it - fixed by correcting the docstring's tense/claim and only filling in the real review section after both reviews genuinely completed. **Lesson reconfirmed**: this specific bug (a migration script's own docstring citing a review as already-done before it's actually done) has now recurred across 2 of 4 real-world batches of this mechanism - worth adding an explicit pre-flight check to any future migration-script template ("does this docstring claim anything about review status? if so, is it TRUE right now, not just true by the time --apply runs?") rather than relying on each pass's reviewer to independently re-catch it. Full detail: `docs/planning-log/2026-09-09-item-village-event-messages-migration.md`. Registry `status != drafted` (done) count: 2446 -> 2460. `item-village-event-messages` chapter's `no_markup_yet` backlog: 14 -> **0** (fully cleared). **This closes out all 4 chapters this session's dispatching task named** (`battle-status-messages` partial/3-held-back-for-the-odd-hl-count-blocker, `village-chief-event`, `board-event-ui-labels`, `item-village-event-messages`) - the odd-hl-count blocker (3 entries total, `battle-status-messages` only) remains the one genuinely unresolved gap in this mechanism, needing a scoped `_check_hl_pairs_single_page()` change (excluding `jp_prologue()`-classified leading hl-like tokens from the pairing count) rather than more translator-authoring passes.

**Follow-up 2026-09-09 - fifth `no_markup_yet` batch (32/32 migrated, 0 held back), spanning the 5 largest remaining chapters: `shop-church-tooltips`, `job-change-office`, `vocab-status-effects`, `blacksmith-gutz`, `musashi-courier` - first time this mechanism has been applied to NAMED-CHARACTER dialogue (not just system-log events), and a real repoint bug found+fixed during `--apply` itself.** `tools/migrate_no_markup_yet_batch_2026-09-09.py`. 3 of the 5 chapters are established personas (Kuria the job clerk, Gutz the blacksmith, Musashi the courier) - tone/voice checked against already-`patched` siblings per chapter before authoring, not assumed. The "registry undersells" gotcha confirmed again in most of the 32. **A genuine registry write-back-gap find**: all 6 `vocab-status-effects` entries' `pointer_array` ref_sites already resolved into the sentinel range with EXACTLY the wording this pass independently derived - fixed as pure bookkeeping (0 new ISO bytes), decoded via the correct `BLOB_ISO_OFF + (vma - SENTINEL_LO)` sentinel-blob addressing formula (never `elf_off()`, which only resolves against `iso/original/original.iso`). **A real repoint bug, found live during `--apply` (not caught by dry run, since dry run never exercises phase4's actual byte-write path): two entries in the SAME batch can share a `lui_vma`** (`0x47ef90`/`0x47efe0`, the "two `addiu` instructions off one shared `lui`" MIPS pattern already documented above in the `code_immediate` id+delta section - but this is the FIRST time two entries sharing this pattern have landed in the SAME migration batch, not just the same already-shipped code). The original repoint loop processed entries independently, so the first entry's write clobbered the shared `lui` with its own new hi16, then the second entry's "verify old pre-image" check read the ALREADY-MUTATED in-memory buffer instead of a frozen snapshot - found garbage and correctly refused rather than corrupt (blob content was already written by phase3, but the `if errors: sys.exit(...)` guard sits BEFORE the disk write, so zero repoint bytes ever reached disk - verified: all pointers/lui-addiu pairs were still original). **Fix, generalizable to any future batch**: (1) validate a `code_immediate` site's "old" pre-image against a FROZEN snapshot taken before the run starts, never against the buffer being progressively mutated by earlier entries in the same loop; (2) track assigned hi16 per `lui_vma` in a dict and raise a clear, explicit error if two entries sharing a `lui_vma` would need different hi16 values for their own new targets, rather than silently letting one clobber the other. **Before trusting a multi-entry `code_immediate` batch, check for shared `lui_vma` across ALL candidates up front** (a one-line dict-of-lists scan) - this cost a wasted `--apply` attempt + backup-restore cycle here, entirely avoidable by checking first. 2 independent adversarial reviewers, both SAFE TO APPLY, both independently flagged the same real finding (`0x48c840` musashi-courier missing the character's "buddy" tag vs. sibling voice - adopted before `--apply`). Live-PINE verified 32/32 MATCH. Registry done count: 2460 -> 2492. Full detail: `docs/planning-log/2026-09-09-no-markup-yet-batch-migration.md`.

**Follow-up 2026-09-09 - sixth `no_markup_yet` batch (32 candidates across 17 small chapters, 2 held back), immediately following the fifth - a concurrent session's encoder fix unblocked 3 previously-documented odd-hl-count holdouts, a NEW write-back-gap variant surfaced (relocated-but-still-untranslated JP), and this project's first mid-stream (post-page-0) speaker-change entries were migrated.** `tools/migrate_no_markup_yet_batch2_2026-09-09.py`. (1) `0x476c30`/`0x476c60`/`0x478e00` - the ORIGINAL 3 `battle-status-messages` odd-hl-count holdouts - were unblocked by a DIFFERENT, concurrently-running session's `text_encoder._exclude_provably_safe_hl_hits()` fix (two narrow provably-safe rules: dead-code-immediately-superseded; leading-permanently-unclosed-baseline). **When another session is fixing shared infrastructure concurrently, re-test its claimed fix empirically yourself (a standalone `derive_en_positional_markup()`/`encode_mixed_markup_stream()` call) before relying on it in your own batch - do not just trust the other session's own docstring/commit claim.** (2) A NEW write-back-gap VARIANT, distinct from the vocab-status-effects case above: `0x488f40` (memory-card-messages)'s `code_immediate` ref_site already resolved into the sentinel range, but the relocated content there was the ORIGINAL JAPANESE, verbatim - some earlier, unrelated space-reclamation pass had moved it without ever translating it. Handled by decoding from the WORKING iso via the sentinel-blob offset formula, content-verifying against the registered `jp`, then treating that sentinel address as the real content VMA to encode/repoint from (same shape as the ordinary "id+small-delta" handling, generalized to a full relocation). **Adjacent bug found+fixed in the same check**: `norm()` (this project's standard `{{...}}`-stripping comparator) replaces markup with a SPACE - safe for English (real word boundaries) but WRONG for Japanese (no natural inter-character spaces), so stripping a marker from real jp text can insert a spurious space that makes an otherwise-identical string compare unequal against the registry's own un-spaced `jp` field. Fixed via a new `norm_jp()` (strips ALL whitespace, not just collapses runs) - **use `norm_jp()`, never plain `norm()`, for any JP-content-identity check; keep using plain `norm()` for EN comparisons, where spaces stay meaningful.** (3) `0x489c70`/`0x489ee0` (hitman-kii) are this project's FIRST entries with a genuine mid-stream (page >0) speaker change - JP's real stream carries `[spk 0x3803]`/`[spk 0x3804]` before pages 2/3, not just the usual page-0 prologue speaker every prior migrated entry has had. `text_encoder.py`'s `SPK_TAG_RE`/`plan_stream_pages()` already support this (write the literal `[spk 0xNNNN]` tag at the right page start in `en_text`) but this project's own migrations had never exercised it before - empirically validated via a standalone encode+decode round-trip (confirmed SPEAKER tokens land at the correct stream positions) before trusting it, not assumed correct from reading the code alone. **2 real holdouts, not forced**: `0x488810`/`0x4888e0` (memory-card-messages, the chapter's other 2 `no_markup_yet` entries) - real jp decode shows `hl:0xb007` reasserted once per real jp LINE (5 lines), all on a SINGLE page, exceeding the standard 3-line box budget - almost certainly an unclassified TALLER window class (this doc's own `h=30n+26` taller-box note above), not simply odd-hl-count; high-visibility system-critical content (shown every boot without a memory card), not risked without a real box-height investigation first. Shared-`lui_vma`/`pointer_vma` collision check done up front this time (learned from the fifth batch's mid-`--apply` surprise) - zero collisions in this batch's 32 candidates. Full detail: `docs/planning-log/2026-09-09-no-markup-yet-batch-migration.md`.

**Follow-up 2026-09-09 - batch 2's own live-PINE verification hit a live-verify TOOLING bug, not a content bug: `phase3_stream_markup()`'s hl-equivalent-pen0 rendering gap (the same bug CLASS as the already-documented ICON-vs-PARAM `build_change_ledger.py` bug, now confirmed in a THIRD independent tool).** The first live-verify run of `tools/migrate_no_markup_yet_batch2_2026-09-09.py`'s 32 entries reported 31/32 MATCH, 1 MISMATCH (`0x478e00`, "PlayStation2 Multitap") - but the "mismatch" was purely cosmetic: `tools/live_verify_no_markup_yet_batch2_2026-09-09.py`'s own `phase3_stream_markup()` rendered this entry's 2 `pen0`-kind tokens (`0xe832`/`0xe864`, both in the `0xE800`-`0xEFFF` hl-equivalent sub-range - see `text_encoder._is_hl_like()`) as raw `<0xe832>`/`<0xe864>` placeholders instead of the canonical `{{HL:0xe832}}`/`{{HL:0xe864}}` the registry's own `en` field correctly uses. Fixed in both this pass's live-verify script and its batch-1 sibling (applied for consistency even though batch 1's own 32 entries never exercised a pen0-hl code) - check `0xE800 <= word <= 0xEFFF` and render `{{HL:}}` for that sub-range, same as `text_encoder.py` already does. Re-ran the full 32-entry live-verify after the fix: 32/32 MATCH. **Any future live-verify script's own markup-rendering function needs the SAME hl-equivalent-pen0 special case `text_encoder.py`'s own `_is_hl_like()`/`zero_width_placeholders()` already carry - copying an OLDER sibling live-verify script (none of which had hit a pen0-hl entry yet) silently propagates this gap forward. Grep for `elif k == "pen0"` in any new live-verify script and confirm it's not just `<0xNNNN>` unconditionally.**

**Follow-up 2026-09-09 - `job-descriptions` (38/39 write-back-gap-fixed, 1 pre-existing unaddressable entry unchanged) - fourth chapter in the "981-entry plain-drafted, no `midcontent_markup_shape` tag" sweep, and the FIRST where box-class precedent (not just content-markup cleanliness) was re-verified via a fresh MIPS trace rather than citing a prior doc.** `tools/apply_job_descriptions_writeback_gap_2026-09-09.py`. Content-markup cleanliness held (all 38 `struct_table_field` entries decode to `{glyph, line, end}` only, zero markup) and the chapter's box-class precedent (`JOB_DESCRIPTION_MAX_LINES=7`, from `2026-09-05-text-box-formulas.md`) also held - but per this pass's own dispatched instruction to verify the precedent for real, both `win_create` (`0x27d0a0`) call sites (`0x26d0a8`/`0x355f98`) were re-disassembled fresh off a clean `original.iso` ELF extraction (`tools/raw_decode.py` - capstone mis-decodes this ELF's R5900 `sq`/`lq`/MMI prologues, see that module's own docstring), independently re-confirming `h=236 -> n=7` at both sites and additionally finding each site uses a DIFFERENT pixel width (302px/464px) - real evidence these are the entry's own 2 `pointer_vma` ref_sites, one per UI screen, not a coincidence. All 38 candidates were a registry write-back gap (content already on disc, matching `en` exactly - the SAME class this chapter's other 16 entries already got fixed for in the 2026-09-08 systematic audit, which explicitly excluded multi-`ref_site` entries; this pass's 38 are exactly that exclusion's leftover). Pure bookkeeping, 0 new ISO bytes. 2 independent fresh Sonnet adversarial reviewers, both SAFE TO APPLY (informational-only findings). Live-PINE verified 38/38 MATCH (full census). Registry done count: 2825 -> 2863.

**A real, pre-existing, still-open render-behavior risk surfaced (not caused by this pass, not blocking it)**: `2026-09-05-text-box-formulas.md` separately states the JP originals for this chapter never use a PAGE token ("headerless, unpaged... zero PAGE tokens across all 55 JP streams") - meaning the shipped game has never exercised a page-advance in this UI element. Yet 20 of the 38 entries this pass touched already carry real PAGE tokens on disc (written by an earlier, unreviewed pass using the standard auto-paginate mechanic, built for boxes WITH a confirmed advance input). Whether the job-description panel actually supports turning to page 2/3, or would silently truncate at page 1 in real play, is UNCONFIRMED - this project has never traced the render loop behind these 2 call sites for controller-input polling / page-index-increment logic. `status: patched` here accurately reflects "content is genuinely on disc, byte-verified" (a DEPLOYMENT-PROGRESS fact) - it does not claim "confirmed rendering correctly," which `emulator_confirmed` is for. Logged as a real, separately-tracked open item, not silently accepted or used to block a bookkeeping fix that cannot change the underlying bytes either way - see `docs/planning-log/OPEN-QUESTIONS-2026-09-08.md` section 10. **General lesson reinforced**: box-class LINE-COUNT precedent and PAGINATION-AFFORDANCE (does the UI actually let a player turn the page) are two SEPARATE claims - re-confirming one (line count, done here via MIPS trace) does not automatically confirm the other, and content that was already on disc before your own pass touched it can still be carrying this exact unconfirmed risk. Full detail: `docs/planning-log/2026-09-09-job-descriptions-migration.md`.

**Follow-up 2026-09-09 - `vocab-status-effects` (14) + `memory-card-messages` (16) - fifth chapter-pair in the "981-entry plain-drafted, no `midcontent_markup_shape` tag" sweep, and the first pass in this sweep to combine write-back-gap bookkeeping AND real fresh sentinel migration in one script.** `tools/migrate_vocab_status_memory_card_2026-09-09.py`. 29 of 30 migrated (16 write-back-gap clean + 1 write-back-gap needing an `en`-field fix + 1 asymmetric write-back-gap + 9 plain real migrations + 2 markup-authored real migrations), 1 held back. Full detail: `docs/planning-log/2026-09-09-vocab-status-memory-card-migration.md`. Registry done count: 2863 -> 2892.

**New, benign `pointer_array` variant of the already-documented "id+small_even_delta" pattern**: 9 of the 14 `vocab-status-effects` candidates have `pointer_array` `ref_sites` that resolve, on BOTH `original.iso` AND the working ISO (i.e. an untouched ORIGINAL pointer arrangement, never a patch artifact), to `id + 2/4/6 bytes` - 1/2/3 leading SPACE-glyph (word `0x0000`) words of padding before the real content starts. `skills/PATCH-MOD-ISO.md`'s existing id+delta note only documents this for `code_immediate` sites (single-glyph padding); this confirms the identical mechanism for `pointer_array` sites too, with a multi-word variant. Decoding fresh at the real content start (`id+delta`) is required to get a clean markup verdict - decoding at bare `id` sees the padding as extra leading glyphs, not a decode error, so this is easy to miss without deliberately checking whether a `pointer_array` site's OWN value already differs from its `id` on the pristine original disc.

**A "registry `en` field silently stale relative to its own already-correct disc content" bug class, found via `0x53492a` and (flagged, not fixed) `0x5348c0`.** Both are instances of this chapter's 8-strong standalone `の` template-fragment family (`event: s`, `s-2`, ... `s-8`), whose real JP source is `{{HL:0xb002}}{{PARAM:0xa000}}{{HL:0xb008}}の`. 6 siblings already got the correct markup-rich `en` (`"{{HL:0xb002}}{{PARAM:0xa000}}{{HL:0xb008}}'s"`) written back in an earlier pass; these 2 entries' disc content ALSO already carries the identical correct bytes, but their registry `en` field was left at a bare, markup-free `"'s"` by whichever pass actually wrote the disc bytes. **A markup-stripping `norm()` comparison cannot catch this** - it strips `{{...}}` from both the correct-rich and the stale-plain candidate alike, reporting "matches" either way. Any future write-back-gap check for a markup-bearing template family should compare the RAW disc render (not `norm()`) against the expected value, or independently spot-check a few already-`patched` siblings' `en` fields for the SAME markup convention before trusting a normalized match. `0x53492a` was fixed this pass (direct `en` dict mutation, matching the established sibling convention, before the bookkeeping status flip); `0x5348c0` is a 7th instance of the identical gap, out of this pass's scope (already `status: patched`), flagged to `OPEN-QUESTIONS-2026-09-08.md` section 11 for a trivial future fix.

**A THIRD tag-absence-adjacent gotcha confirmed while investigating this bug**: this template family's real disc content carries a trailing PAGE break (`//`) that the established sibling `en` convention deliberately OMITS - JP's own real bytes have the identical trailing `//` (confirmed on `0x53492a`'s own JP source), so this is a template-mechanism artifact (this fragment is presumably concatenated with a FOLLOWING stream at runtime), not missing markup or a translation gap. A write-back-gap check for this family must strip exactly one trailing `//` before an exact-match comparison - not a lossy generic `norm()` (which would hide a real markup-content mismatch too), and not a bare exact-match (which would false-positive-FAIL on this legitimate structural artifact).

**`0x488f10` ("Save to a new file?") re-confirms rather than contradicts a 2026-09-07 finding, but only after a first attempt hit the classic ELF-vs-sentinel-formula false-corruption trap live, mid-pass.** The registry's own pre-existing 2026-09-07 note already found this entry's 2 `code_immediate` `ref_sites` are asymmetric (one real, functioning site; one that "does not reflect a real functional connection"). Both sites' CURRENT targets have SINCE shifted into the sentinel range (sentinel space has grown/been reallocated multiple times since 2026-09-07) - decoding both via the plain ELF-offset formula found BOTH now fail, which is exactly `skills/PATCH-MOD-ISO.md`'s documented "wrong formula on a sentinel address silently reads garbage instead of erroring" trap, not a real regression. Redone with the correct `BLOB_ISO_OFF + (vma - SENTINEL_LO)` formula: one site decodes cleanly to the exact registered `en`, the other still fails. **Lesson generalized**: before concluding a previously-known-good `ref_site` has gone stale/dangling, always re-verify its CURRENT target using the address-range-appropriate formula (check whether the target falls in `[SENTINEL_LO, SENTINEL_HI)` first) - the "both sites broken" symptom this pass initially saw was 100% a decode-formula bug, not a real disc-content regression, and would have wrongly held back an easy, safe write-back-gap fix if trusted at face value. An independent fresh adversarial reviewer's own re-derivation additionally found the "bogus" site (`lui_vma=0x2c0a54`) actually shares that `lui_vma` with a DIFFERENT, already-`patched` entry (`0x488f40`, `addiu_vma=0x2c0a5c` vs this site's own `0x2c0a60`) - explaining why its resolved target drifted over time without `0x488f10` itself ever being touched: genuine dead-code/register reuse, not corruption.

**A THIRD confirmed instance of the live-verify-tooling pen0-rendering false-positive class (same bug CLASS as the ICON-vs-PARAM `build_change_ledger.py` bug and the hl-equivalent-pen0 rendering gap already documented above, now for a THIRD, differently-scoped pen0 sub-range).** `0x4886b0` ("New File")'s real, PRISTINE-ORIGINAL JP source (confirmed on `original.iso`, not introduced by any patch) carries a leading `pen0:0xb80a` (pen-X-set, type 23 - a horizontal cursor-positioning code, zero visible glyph content) before the glyph content. This pass's migration script's own `render()` (used for the write-back-gap content check) already correctly treats any `pen0` outside the `0xE800-0xEFFF` hl-equivalent sub-range as zero-width and silently drops it - but a live-verify script freshly adapted from an OLDER sibling (which only special-cases the hl-equivalent sub-range, per the ALREADY-documented gotcha above) rendered it as a literal `<0xb80a>` placeholder, producing a false "MISMATCH" (`'<0xb80a>New File'` vs registered `'New File'`) on an entry whose disc bytes were never touched by this pass at all (pure write-back-gap bookkeeping). Fixed by matching the migration script's own convention (drop non-hl-equivalent `pen0` silently) in the live-verify script too. **Lesson re-generalized a 3rd time**: `grep -n 'elif k == "pen0"'` (or equivalent) in ANY live-verify script and confirm ALL pen0 sub-ranges get the SAME treatment the authoritative encoder/render function already uses for that content class - copying an older sibling script propagates whichever subset of pen0 handling that script happened to need, not the full picture.

**2 independent fresh Sonnet adversarial reviewers**: Reviewer A verdict SAFE TO APPLY outright (full 30-entry independent re-classification from raw bytes, independently found the `0x488f10`/`0x488f40` shared-`lui_vma` explanation above). Reviewer B verdict SAFE WITH CHANGES NEEDED - 2 real, non-blocking tone/consistency findings, both fixed before `--apply`: (1) `0x53497c` "All-Up" -> "All Up" (no hyphen), matching sibling `0x53476c` "All Down"'s established un-hyphenated convention for this stat-buff family; (2) `0x488e80` was missing its terminal period, inconsistent with every sibling in the chapter. Both reviewers independently re-derived the sentinel-blob capacity math and confirmed the 11 real migrations (534 raw / 578 aligned bytes) fit inside the 736 free bytes already allocated, needing no sector-count bump.

**Apply + live-verify**: `--apply` completed 0 errors (11 real repoints + 18 write-back-gap bookkeeping fixes), sector count unchanged (120, no loader-trigger hook rebuild needed), `iso/original/original.iso` sha256 unchanged throughout. Live-PINE full census: 29/29 MATCH after the pen0-rendering fix above (first run: 28/29, the 1 false-positive mismatch being exactly that tooling bug, re-confirmed as a live-verify-only artifact - not a re-decode of different content). Registry done count: 2863 -> 2892, `drafted` count: 726 -> 697.

**Follow-up 2026-09-09 - `vocab-regions-cities` (11/11 migrated, 0 held back) - sixth chapter in the "981-entry plain-drafted, no `midcontent_markup_shape` tag" sweep, and the chapter with the strongest precedent ratio yet checked (61 already-patched siblings, 11 remaining) - confirms strong precedent still needs real per-entry verification, not a rubber stamp.** `tools/migrate_vocab_regions_cities_2026-09-09.py`. All 11 decode genuinely plain (`{glyph, end}`/`{glyph, end, space}` only). **A real structural difference from the 61 siblings, found by checking rather than assuming**: all 11 drafted entries carry TWO `pointer_vma` ref_sites each (two separate pointer tables, presumably two UI screens); all 61 already-patched siblings carry only ONE - exactly the multi-ref-site shape the original 2026-09-08 systematic writeback-gap audit deliberately excluded, so this needed its own real per-site check rather than trusting the single-site sibling pattern. 8 of 11 were a clean write-back-gap (both sites already resolved to the same sentinel address, content byte-exact to registered `en`).

**A 5th/6th confirmed instance of the "untracked in-place edit truncated by the live padding-skip pointer" bug class** (Africa `0x534ebc`, Atlantis `0x534ede`), same as `skills/STRING-REGISTRY.md`'s already-documented `0x53464e`/`0x534666`/`0x534692`/`0x5346aa` case: original JP source has leading space-glyph padding, both `pointer_vma` sites correctly point PAST it (`id+delta`) on `original.iso`, but some earlier untracked pass wrote the English replacement starting at BARE `id` instead of `id+delta` - the live (unrepointed) pointer, still reading `id+delta`, renders a truncated tail ('rica'/'tlantis' instead of 'Africa'/'Atlantis') as a genuinely LIVE, currently-shipping bug on the working ISO, confirmed by a pre-migration live-render check and independently re-confirmed by 2 adversarial reviewers with wide-window (32-64 byte) decodes. Fixed the established way: real sentinel migration, repointing both sites away from the broken in-place bytes (old bytes abandoned in place, confirmed harmless - zero `pointer_vma`/`id` collisions anywhere in the registry). **Recurring enough now (2 fresh chapters, 6 total ids) that any future chapter with `pointer_array`/`code_immediate` id+delta padding should have its LIVE (working-ISO) render checked at the delta-adjusted address specifically for a truncated-tail shape before trusting "resolves to id+delta, unmigrated" as simply "untouched, needs a fresh migration" - it may already hold live, subtly-broken content instead.**

**A genuinely NEW variant, not previously documented: content already CORRECT in-place, but non-standard versus 100% of the chapter's siblings.** Mu (`0x534ef0`) has zero leading padding and its content at bare `id` already decodes correctly to `'Mu'` on the working ISO (2 katakana glyphs -> 2 latin glyphs, same length, no truncation - genuinely not a bug, the live unrepointed pointer reads correct text today). But explicitly checking found 0 of this chapter's 61 already-patched siblings have `landing_vma == own id` (100% sentinel-relocated) - so rather than invent a one-off "leave it in-place, bookkeeping-only" classification that diverges from every sibling's mechanism (and risks a future audit script misreading `landing_vma==id` as anomalous), it was migrated through the same standard sentinel mechanism as its batch-mates, for consistency with the chapter's 100%-sentinel precedent. **General lesson: "content is already correct" and "content is on-mechanism with its siblings" are two separate claims - the first alone does not automatically mean a bookkeeping-only fix is the right call if it would leave the ONLY entry in a chapter not using the established sibling mechanism.**

Box-class precedent was NOT freshly MIPS-traced this pass (unlike `job-descriptions`) - deliberately: every candidate `en` (max 13 chars) is shorter than several already-shipped siblings in the SAME chapter ("Southern Cross" 14 chars, "Costa Rica" 10 chars), so the unclassified-pool `LARGE_BOX_MAX_CHARS=22` placeholder applies with wide margin regardless of the real box class - a legitimate scope decision, documented explicitly rather than silently skipped.

2 independent fresh Sonnet adversarial reviewers, BOTH verdict SAFE TO APPLY outright (neither "with changes needed") - both independently re-derived every claim from raw bytes with their own throwaway decoders (never reusing the target script's own `render()`/`norm()`), including the Africa/Atlantis truncation bug, live sentinel-range re-derivation, byte-capacity math, and zero `pointer_vma` collisions project-wide. `--apply` completed 0 errors (3 real repoints + 8 write-back-gap fixes), sector count unchanged (120, no hook rebuild needed), `original.iso` sha256 unchanged throughout. Live-PINE full census: 11/11 MATCH, kill-switch never fired. Registry done count: 2892 -> 2903, `drafted` count: 697 -> 686. `vocab-regions-cities` chapter: 61/72 -> **72/72 (fully cleared)**. Full detail: `docs/planning-log/2026-09-09-vocab-regions-cities-migration.md`.

**Follow-up 2026-09-09 - `vocab-shop-verbs-misc` (20/21 migrated, 1 held back) - seventh chapter in the sweep, richest single-chapter find yet: a NEW ref_site bug class (3 entries) plus 5 truncated-live-text bugs found in one chapter, plus a real OOM-kill mid-`--apply` recovered cleanly.** `tools/migrate_vocab_shop_verbs_misc_2026-09-09.py`. Mixed `ref_type` (14 `code_immediate`, 5 `pointer_array` incl. 1 hybrid, 1 `unknown`/0-sites) confirmed the prior pass's own warning to check per-entry shape rather than assume uniformity. Full classification: 1 held back (genuinely unaddressable, no `ref_sites`) + 6 write-back-gap (3 sentinel, 3 genuinely in-place - this chapter has its own precedented `inplace-yes-no` mechanism, unlike `vocab-regions-cities`'s 100%-sentinel chapter) + 3 "shared-delay-slot-lui mispairing" `ref_sites` corrections (see `skills/PATCH-MOD-ISO.md`'s new entry for the full mechanism) + 5 truncated-live-text bugs (found via a FULL byte-level orig-vs-work comparison at each real `content_vma` - checking that a `ref_site` resolves to the same address on both isos is necessary but NOT sufficient to prove "untouched," 2 of the 5 were missed on a first pass that only checked site agreement) + 6 plain never-touched migrations. 2 independent fresh Sonnet adversarial reviewers, BOTH verdict SAFE TO APPLY outright, including independent hand-disassembly confirming the ordinary (non-"likely") branch opcodes the whole ref_site-correction claim depends on. The first `--apply` attempt was killed by the OS OOM killer (pre-existing system memory pressure meeting this project's standing multi-full-ISO-buffer-in-memory pattern - see `skills/PATCH-MOD-ISO.md`) - recovered via file-timestamp forensics + a full independent fresh re-verification of every entry against the already-migrated ISO, then a memory-light recovery script completed just the missing registry write-back (0 ISO bytes touched by recovery). Live-PINE full census: 20/20 MATCH (extended live-verify script handles BOTH sentinel-indirection AND direct in-place addressing per entry). Registry done count: 2903 -> 2923, `drafted` count: 686 -> 666. `vocab-shop-verbs-misc` chapter: 57/79 -> 77/79 (2 remaining: the 1 held-back entry + 1 pre-existing entry outside this pass's scope). Bonus: a quick, non-deep characterization pass on 17 "singleton straggler" chapters found 7 more trivially write-back-gap-fixable entries and 1 trivial fresh migration, ready for a future quick-win follow-up. Full detail: `docs/planning-log/2026-09-09-vocab-shop-verbs-misc-migration.md`.

**A FIFTH tag-absence-adjacent gotcha found 2026-09-09, `battle-status-messages-3`'s "10 fresh candidates" - a recommended chapter's own candidate list can be pre-tagged and still get handed off as if it were untagged-981-bucket content, if nobody checks the tag before recommending.** The item-village-event-messages2 pass's own recommendation named these 10 ids by simple arithmetic (17 drafted - 7 already-held-back-for-0xe04a-class = 10 "genuinely fresh") - a real, fresh per-entry check found **all 10 already carry a `midcontent_markup_shape` tag** (`readiness: blocked_true_pen0_position`, tagged 2026-09-08) - they were never untagged at all, just not yet migrated. This is a DIFFERENT failure mode from the 4 tag-ABSENCE root causes already documented above (`struct_table_field` skip-list, `dungeon-label`'s genuine markup-freedom, the prologue-vs-content scope gap, the `>1 ref_site` skip) - here the tag exists and is accurate, but a hand-off recommendation's own arithmetic ("N total minus M held-back") silently assumed the REMAINDER was untagged-bucket content without checking. **Lesson: before treating any recommended candidate list as "untagged, no_markup_yet-shaped," check each id's own `midcontent_markup_shape` field directly - a chapter can have BOTH untagged AND already-classified-but-unmigrated entries mixed in its `drafted` count, and simple subtraction doesn't tell them apart.**

**Real payoff once decoded correctly: `text_encoder.encode_pen0_positional_stream()`/`decode_ui_grid_stream()` (the true-pen0-position UI-grid template-splice mechanism, built 2026-09-08 for the board-event-ui-labels Settings screen, proven a 2nd time on the Controls screen with zero code changes) now confirmed a 3rd/4th time on a STRUCTURALLY DIFFERENT UI class - a nav-menu button bar** (`0x479650`/`0x4796a0`/`0x479c80`/`0x479cb0`/`0x479d00` - each button its own PEN-X-set-preceded glyph run, LINE-separated, no player-facing "/" separators - those in the drafted `en` were a human transcription convenience only), plus a duplicate internal "Scale End" system label pair (`0x478cf0`/`0x478d10` - NOT PEN-X-set bounded, see the correction below), a shop-title template (`0x4797e0` - "Item Shop" is the entire translatable content; the remaining 51 tokens, a 6x-repeated item-slot icon/param8/hl template with real 8-byte param8 payloads, reproduced byte-for-byte verbatim, confirmed byte-identical modulo the title's own length shift by 2 independent reviewers), and a gauge label with a fixed separator icon (`0x479e00`, "Dark Aura"/icon/"Points" - the icon is a FIXED, non-substituting glyph, not a runtime value slot). **Reviewer-caught correction, real and worth generalizing**: not every entry migrated via this mechanism actually has the PEN-X-set-bounded shape the mechanism's own pixel-safety argument depends on - `0x478cf0`/`0x478d10`'s glyph-run boundary codes are actually type-27 (`0xD801-0xDFFF`, "unclassified beyond 0 extra bytes" per `dialog_codec.py`'s own comment) plus one HL color code, NOT PEN-X-set. Encoding is still byte-safe regardless (verbatim template-splice reproduces whatever the boundary code actually is, correctness doesn't depend on WHICH control code it is) - but the STRONGER "a too-wide replacement can only overflow into empty margin before the next run's fixed position" pixel-safety argument (the Settings-screen design doc's own load-bearing claim, backed by a real screenshot pixel-correlation) only transfers to entries that are genuinely PEN-X-set-bounded. **Always verify the specific boundary-code TYPE per entry, not just "this chapter uses `encode_pen0_positional_stream()` so the mechanism's whole safety story applies uniformly."**

**1 genuine hold-back, not forced: `0x478d30`** (a PlayStation2-exclusive-Multitap system message) - real JP decode shows 6 real LINE-broken visual lines (1 genuinely blank) plus a mid-sentence PEN0 "table coordinate" token (`0x4801`, type 9) standing in for a controller-button icon, but **zero PEN-X-set tokens anywhere** (confirmed independently by 2 adversarial reviewers) - unlike every migrated sibling in this batch, there is no per-run absolute cursor reset, so the mechanism's core safety property doesn't hold. No established box-height/width precedent exists for this system-message UI class project-wide (unlike the standard 3-line box or job-descriptions' 7-line panel). Flagged to `docs/planning-log/OPEN-QUESTIONS-2026-09-08.md` section 13, `status` left `drafted`. **A second, smaller open item** (Reviewer B): `0x4797e0`'s title run is the ONLY run in the batch with no preceding PEN-X-set of its own (position set by caller code outside the string) - "Item Shop" (9 chars) vs. "アイテム屋" (5 glyphs) fitting the same slot is genuinely unverified, `status` left `patched` (byte-verified, not yet visually confirmed) pending a future owner screenshot - the project's own established "patched != visually confirmed" distinction already covers this gap without blocking further sweep work.

2 independent fresh Sonnet adversarial reviewers: Reviewer A verdict SAFE TO APPLY outright (independently re-derived all 10 candidates' real structure including the whole-registry write-back-gap re-check for all 10, not just the 9 migrated; independently confirmed the shared-`lui_vma` pair `0x478cf0`/`0x478d10` - 0 project-wide collisions - lands in the same 64KB hi16 window; independently byte-diffed the Item Shop template as identical). Reviewer B verdict SAFE WITH CHANGES NEEDED - the 2 corrections above (both documentation-accuracy fixes, no functional bugs), applied to the migration script's docstring and the registry `note` text before `--apply`. `--apply` completed 0 errors (9 real repoints, sector count unchanged - 664 bytes needed of 2,008 free, no loader-trigger-hook rebuild), `original.iso` sha256 unchanged throughout. Live-PINE full census: 9/9 MATCH, kill-switch never fired. Registry done count: 2967 -> 2976, `drafted` count: 599 -> 590. `battle-status-messages-3` chapter: 9 newly `patched` + 8 remaining `drafted` (7 pre-existing 0xe04a-class held-back, unchanged + 1 new hold-back `0x478d30`). `tools/build_change_ledger.py` crashed on `0x488f10` - re-confirmed (via a scratch instrumented copy, reproduced identically on the pre-this-pass backup ISO) as the SAME already-documented pre-existing known-bogus-`ref_site` gap, unrelated to this pass. Full detail: `docs/planning-log/2026-09-09-battle-status-messages3-pen0-migration.md`.


## Go migration: variable substitutions and source context (2026-10-17)

Use one source classifier for report decoding, encoder marker-family checks and
strict validation. PARAM/ICON spellings denote the same self-contained source
word; they do not make opaque payloads safe or give a variable a known width.
The shared Go grammar checkpoint adds no function, schema or per-script handler.

For the three 69-entry migration clones, current canonical English supersedes 17
historical texts. Literal encoding omits 14 source speakers and 39 trailing PAGE
pauses, so source-context preservation must precede layout acceptance. A symbolic
width model needs proven argument-domain and render-state semantics: the type-20
string renderer can execute nested controls through the generic dispatcher.
Thirty-five entries cannot fit an unchanged universal source-page envelope even
at zero variable width. Recover actual consumer geometry and value bounds rather
than assigning a guessed character width or dropping source boundary checks.

When inspecting PS2 instructions with standard Capstone, retain raw words and mark
R5900 SQ/LQ/MMI encodings opaque; standard MIPS DSP mnemonics can be incorrect.
Bounded source captures and unchanged stats are investigative evidence, not a fresh
whole-image hash, gameplay check or approval to apply. See tools/go/analysis/
variable-substitution-contracts.json for the frozen sources and next obligations.


### Go source context contract (2026-10-18)

The existing Go encoder/planner now have an opt-in source-context contract, requiring
measured layout. Keep existing literal recipes unchanged. Decode the pinned source
against the same canonical English so marker values/order are checked; preserve the
source prologue and initial speaker rather than guessing or repeating speakers on
later pages. Original Python appends ONE final source PAGE independently of English
`//`: nine captured canonical cases therefore end in TWO PAGE words. Deduplicating
those pauses changes the reference behavior. Independent `prefix_words` refuse.

Mandatory layout is load-bearing: an independent review reproduced acceptance of
unbounded 0x9000 substitutions when the candidate allowed a nil layout. The repaired
shared table guard and source-native metric refusals remain mandatory. Context-only
encoding is not auto-wrapping: original per-entry policies change51of69outputs and
add19automatic pages in18entries. Prove actual geometry/value domains and explicit
page behavior before whole-path migration or real-copy application. Root and ordinary
review checks are in tools/go/evidence/source-context-checkpoint.json; no new function
or recipe was added, and the69entry family remains uncredited.

### Read-only numeric and formatter investigation (2026-10-18)

R5900 SPECIAL MULT can write the low product to its encoded `rd` as well as HI/LO.
Standard Capstone printed the divisor helper's raw00441018 as an accumulator
operation; its actual fields are rs2/rt4/rd2. The existing manual decoder also
omits that destination. Retain raw fields and qualify tool output; the primary
[PCSX2 implementation](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/R5900OpcodeImpl.cpp)
corroborates the EE destination semantics. A bounded delay-slot-aware self-check
of the owned capture returns10^8 and verifies exactly15 END-filled halfwords for
the numeric buffer. This is not hardware emulation or proof of caller bounds.

The owned source14 capture has actual digits0..9, sign/separator glyphs, and three
leading suffix pointers. Do not name the selector's meaning without tracing its
writers. Unchecked large signed32 values index outside the decimal table, where
actual words include controls. Keep variable-width refusals until each caller's
domain and renderer state are proven. Read signed address immediates carefully:
LUI0x57 plus-0x1440 is0x56ebc0, not0x57ebc0.

Keep character-budget wrapping separate from physical measurement. The owned Go
prototype uses one successor array instead of cloned line lists for every span;
both state storage and search operations need explicit resource bounds. Integrate
formatting before the existing encoder's highlight-page check and source final
pause, then pin the final bytes. Do not duplicate those checks in a second parser.
Existing literal event recipes intentionally add content pages, so a global stricter
PAGE signature would change established behavior. New source-context character
budgets need their own explicit final-byte/copy review while preserving measured
width, height, ordered-control and unresolved-substitution checks. The isolated
prototype and static captures do not supply application, physical-fit or coverage
credit; see the current tools/go/.goal/GOAL.md for pinned artifacts.


### Verified Go formatter/numeric pilot and fixture reuse (2026-10-18, 17:54 UTC)

The formatter/numeric pilot is now in `tools/go`; the earlier investigative status
above remains historical. `evidence/formatted-events-checkpoint.json` records the
new exclusive-copy application, its original recipe/binary hashes and full-image
containment. The promoted recipe changes only evidence wording; never attribute
an earlier application receipt to that new data hash or a later build. It is a
separate exact-source branch from the 172-event/Menu outputs.

Reuse the existing font fixture for the same source and add only missing measured
metrics. The pilot needs nine additions, not another copy of hundreds of entries.
When decoding the base fixture into the existing test struct, clear its entry map
first: `json.Unmarshal` merges map keys, so restoring an aliased saved map would
silently retain the parent's entries. Keep the child's entries and policy separate.

Statement coverage is a selection lead, not a semantic-equivalence proof. The
initial 35 KB fixture retained all 97 reached blocks but missed three plausible
policy mutations. Two original reference cases restored those contracts; the final
36 KB fixture retains all 69 canonical outputs and detects the 11 bounded policy
mutations checked. Keep the larger differential corpus pinned separately.

Pointer slices preserve JSON `null` range entries so the existing validator can
refuse them. An empty range object still declares `0..0`; reviewed recipes must
state actual caller bounds. CLI refusal tests must assert the intended error and
use the original glyph JSON bytes; re-marshaling those bytes yields a base64 string
and can make an unrelated input failure look like a successful safety regression.


### Compatible Go append tables (2026-10-18, 18:30 UTC)

Select same-source tables as one ordered transaction through existing `plan`.
Reserve every explicit old read span before the first allocation, share one cursor
and immutable raw-reference index, and retain inspection/scopes/encoding/geometry
per table. Native equality excludes only documented local ranges and character
budgets; source/mapping/font/native pins remain exact. Do not union landing ranges
or rewrite staged-source hashes. Existing directory lexical order then numeric IDs
determines allocation; reversing tables may legitimately change target addresses.

The native14 directory combines172literal+1formatted entries using unchanged recipe
bytes and the existing CLI. Originalsingle172selection retains its old Menu chain;
combined173has no reviewedMenu successor. Test later old-read reservations, complete
new-output/bookend spans, all table orders, mixed done/pending states and writer
binding independently. Old-read spans and new-payload bookends have different
lifetimes; do not add speculative +2 reservations without tracing their contract.
See tools/go/evidence/append-composition-checkpoint.json for two fresh reviews,
exclusivecopy/fullcontainment and honest capability-growth accounting. No emulator,
gameplay or historical-path closure follows from that proof.


### Retire completed fixed authoring executors (2026-10-18, 19:09 UTC)

Inspect the whole dated script's selector and duties before retiring its executor.
A NEW_EN dictionary is insufficient: writebacks may be selected after preflight,
and held-back notes can have later canonical dispositions. Compare exact selected
IDs, original ledgers, current canonical fields, explicit reference corrections,
notes and superseded wording. Preserve remaining native/domain/layout/report work;
executor retirement alone earns no whole-path Go credit.

Use the existing main as an unconditional refusal stub and the existing legacy
lookup gate for launcher execution. No new engine or import wrapper is needed.
Direct refusal must remain safe even when the central disposition is missing or
malformed. Verify exact original source in a pinned reachable Git commit and keep
pre-edit backups through review. Do not copy stale drafts into new runtime tables.
Canonical wording stays authoritative; full source retrieval uses git show COMMIT:PATH.

Keep the frozen410-path baseline historical. Broad inherited source/receipt drift
must not be hidden by blanket refreshes or proof repinning. Existing lookup returns
a copy of the historical row with an explicit qualifier covering both source facts
and verification status. Describe does not read the current execution ledger;
missing/malformed dispositions still permit historical inspection. Record current
stub facts separately using existing source_evidence. Enhance existing refusal
tests for canonical/flat/root routes, direct mains and fresh CLIs, no-I/O spies,
fixture preservation and original-row preservation; no new helper/test function.

For full Python verification, put --basetemp UNDER the same owned TMPDIR returned
by tempfile.gettempdir(), not in a sibling directory. Texture fixture guards enforce
that containment before creating synthetic discs. Retain failed runner evidence,
correct the runner without weakening guards, and compare complete test-ID/failure
sets against the known baseline. Current closure is8791cases/8722passes/same69fails,
not all green. Source/data pins must stay fixed for the run. The first retirement
removes90125active source/data bytes and12functions; tests/evidence/docs/backups and
Git history are separate costs. See tools/go/evidence/stale-authoring-retirement-checkpoint.json.


### Fixed replay retirement: later selections and proposal provenance (2026-10-18)

The second executor retirement removes137,548active source/data bytes and13functions,
with no new function; existing test grows94B by sharing one explicit six-path tuple.
Root full8791 retains exactsame69 failures and507 frozen inputs. Scope includes
129+26+32authors,12+6writebacks and45+2heldback notes; later-selected writebacks must
be extracted from main, not inferred from its initial drafted/readiness loop.
The tuple must remain independent of the execution-policy ledger: deleting a
retirement flag must make the test fail rather than silently shrink its coverage.
See tools/go/evidence/fixed-authoring-batch-retirement-checkpoint.json.

For further candidates, distinguish applied history from superseded proposals.
A ledger with dry_run=true is not evidence that the executor applied, even when
its predicted landings match a later pass. Check source-created conditional notes,
reverify-only IDs and whole-registry guards separately. A current patched status
or centering note does not establish control-domain, native-height or CFG proof.
Dynamic source predicates need their actual current count/set captured; the old
regions/cities drafted predicate now matcheszero, not the fixed11 historical IDs.
Preserve semantic argument identities: flagged-prologue0x459800 PARAM8800 means
a curse-target player name; it must not be treated as a numeric debt amount.


### Keep retirement history distinct from current native facts (2026-10-18)

The next five-executor checkpoint is sealed at
tools/go/evidence/fixed-replay-retirement-checkpoint.json:159,579active bytes
removed after policy growth,19functions removed,0new,test+272B separately. Full
8791 retains the same69 inherited failures and507inputpins; ordinary200CLI and
6mutation checks pass. Across three batches:387,252B and44functions removed.
Do not infer whole-path coverage from that deletion; counts remain8/5/11/386.

Historical source and notes can be superseded. Singleton0x47e770's allegedly dead
site was restored as a live fall-through on2026-09-30. The asymmetric memory-card
entry's old0x2c0a54 site was corrected to0x2c0a50; retaining its historical
nonfunctional note does not prove the current connection either way. Qualify these
facts rather than copying an old diagnosis into a new recipe or responsibility.

The charcreate07d/07f scripts have no initial drafted-state guard; they read ELF/ISO
before historical checks. Patched registry status alone cannot prove safe refusal.
Static six-ledger reconstruction records equal100sectors/0x32000 while a whole-blob
rebuild reuses the oldintro slot for Weak and clears the oldgender slot.07f restores
the same180payload bytes at fresh offsets. Do not describe both old slots as dead
space or invent a loader defect from that history. Same allocation size never
establishes preserved payload ownership; actual applications still need fresh old
bytes, independent complete expected effects, readback and whole-image containment.


### Seven historical executor retirements (2026-10-18)

Checkpoint `tools/go/evidence/seven-replay-retirement-checkpoint.json` seals seven
executor-only refusals, not native/full-path coverage. All duties, including metadata-
only shifted entries, JP-only corrections, writebacks and unapplied held proposals,
were enumerated before retirement. Historical equal sector counts did not prove
slot ownership: charcreate oldintro was reused by Weak; original gender was zero.
Later reference corrections supersede old dead-site claims. Ordinary review pins
may be objects containing sha256/bytes/equality, not plain strings; verify their
actual shape. Exact8791/same69 regression, independent280CLI/eightmutations and
root Go checks passed; whole suite is not allgreen. Four-batch697553B net excludes
tests/docs/evidence; composition1894B is a separate cost. Astra015 is adversarial
evidence only, not approval or a replacement for the root seal.


### Eight executor retirements and EOF-only phase checks (2026-10-18)

`tools/go/evidence/fixed-history-retirement-checkpoint.json` preserves275actualduties
andtwoIDsuccessors/twostilldraftedcases. Markupledger138hasNOEN/refsitefields; source
writesmachinefieldsonly. Charcreate07eNOlandingwrite despiteobservedmatchingcurrent
landing. Settings2streams370B/differ25words: identicalJPisnotreusablepositiondata.
Root44fullsourceformattedappends andindependentreadiness preservehistoricalnotes,
missingcitations andlaterreference/landingfixes withoutnewnativecoverage.

Actual`git diff --no-index --check` caughtEOFblanklines missedbyline.rstrip. Clean
changedno-indexdiff mayexit1withNOoutput; warningexit3isnotclean. Waitforfrozenfull
runterminalbeforefixing. ForoneEOFbyteonly, preservefullpreformatreceipt/pins, assert
wholeASTequalityandeveryotherinputunchanged, thenfinalfocused/CLI/lint/whitespace
checks; don'trepinoldfullresultorpretendafinalwhole-suitererun. Finalordinary8491022f
closesLOW. NeverassumeallreviewpinJSONhaveoneshape:inspectactualfiles/recordsfirst.

FutureUI-gridcodecneedsactualconsumercontract: localPythonB000zero-payloadoverride
contradictsnarrativeopaque8Bgrammar. Parsingcleanly/oldpixelreportsdoNOTauthorizea
globalclassificationchangeorwidthwaiver. Reusecontrols/encode/planonlyafterbounded
source/handler/position/canonical-wordingownershipproof; unknownsremainrefusals.


### Source-template positional labels (2026-10-18)

Go checkpoint `tools/go/evidence/positional-labels-checkpoint.json` verifies bounded
Settings/Controls encoding from canonical summaries,3entries/5pairs. Native source
cursor advances2B; B000/D800 consume external varargs in those callers. Default
narrative PARAM8 remains unchanged. Existing encode/controls/plan/writer own the
path,0newfunctions; wholeoutput pins are byte contracts, not widget/ink fit. FullGo
race/build/vet and131original/native-word bytes pass; read-only source14plan13edits
preserves source/canonical. No imageapply/fullpathclosure. Runtimecost9938B included
inaccounting. Keep Python decoder/runfinder while4liveverifiers still call them;
Serena's older boundedmirror omittedthosecallers, augmentwithcurrentrootsymbolsearch.


### Reference producer retirement and summary accounting (2026-10-18)

Go discovery reports retain candidate-only authority. Aggregate counts must be
computed from returned rows, with null content checks distinct from mismatches;
a mismatch remains resolved but advisory. Compare complete prior JSON values
before crediting a summary-only change. Keep dated artifacts in place when a
consumer still reads their schema, even after retiring the producer. Explicit
reviewed machine plans use the existing registry writer; do not pipe heuristic
candidates directly into updates. A metadata correction after a frozen full run
gets a separate bounded receipt and focused checks, never a silent receipt repin.
See `tools/go/evidence/reference-retirement-checkpoint.json`.


### Superseded native repairs and flat facade imports (2026-10-18)

Check both branches and canonical siblings before replaying a historical word
restoration. Current `0x26ed64` correctly serves `0x459bc0`; restoring the former
vanilla high half would break that later translation. Preserve the counterexample
and source-bound proof rather than repinning the old expected bytes. Retired repair
aliases reuse the central refusal gate. Imports in code executed by the flat facade
must use the canonical absolute package; a relative import can resolve against the
facade's shallower namespace. Existing tests cover both owners in the same cases.
See `tools/go/evidence/native-pointer-retirement-checkpoint.json`.

### Diff-first Go reconstruction stages (2026-10-19)

For a pristine-derived Go scratch ISO, compare the entire image with shipping,
then assign changed sectors to ISO files and typed operations before writing
recipes. A byte diff identifies candidates, not reader contracts or patch
ownership. The 142 changed CMB members were replayed by name and bounded
source/target hashes; the original fixed-field tables were reused on a later
source through tiny `reuse_table` manifests pinned to the table hash and
new full-image source hash. Do not copy row facts just to update a stage pin.

Before each isolated apply, independently review every source and target span,
predict the full-image hash, and require exact source identity. Apply to a new
exclusive output, then rehash the output and protected images and reconstruct
the output from source plus declared edits across the *whole* disc. Recompute
the remaining shipping gap; a successful byte stage does not close a historical
script path or prove rendering/gameplay. A canonical END-terminated payload and
shipping-equal pointer site still need a traced runtime reader or copy bound
before promotion; the 15-row draft in
`tools/go/analysis/remaining15-consumer-contract.json` remains held.

The Go `stream_append` reflow switch is per row: a reviewed END reader,
exact shipping encoding hash, source pin, output-byte ceiling and native-font
width/line bounds are required. It may move LINE/PAGE only while preserving
ordered non-layout controls and meaningful boundary signatures; changing a
trailing/empty boundary or PAGE inside active highlight refuses. Audit021 found
that target-only boundary emptiness silently allowed deleting a source pause;
reuse the existing source/target boundary equality check. The 40-row hint-NPC
recipe is held as executed evidence because every target deletes a source
trailing PAGE, despite a shipping-equal isolated byte proof. The old drafted migration's chapter P95 and
consumer tracer are useful leads, not blanket permissions to loosen Go guards.


### Exact frozen current-mod rebuild (2026-10-19)

`tools/go/build-current.sh ORIGINAL_ISO NEW_OUTPUT_ISO` builds the Go runner
and runs three source-pinned transactions: existing allocation plus loader,
whole named `SLPM_657.50` from a pinned ZIP, then existing 142 CMB member facts.
`iso_file_replace` extends the shared bundle planner and ISO name resolver;
its exact extent/size/preimage and bounded ZIP checks feed the existing
exclusive-copy writer. `output_sha256` is enforced after readback, with owned
output cleanup on mismatch. A CMB `reuse_table` alias changes only source/output
image pins, preserving the base JSON hash, bundle-relative path and every member
fact. Repeated `--recipes` composes existing tables without copying their rows.

Two independent reviews of the final pinned inputs preceded the actual run.
`tools/go/evidence/current-build-proof.json` proves every output byte equals
shipping SHA `817962e2…226c3`, all changes belong to the declared edit union,
and protected inputs retain their hashes. This is artifact reproduction, not
semantic migration, individual editability, new art approval or gameplay proof.
Keep held semantic recipes held even when the snapshot includes their shipped
bytes. Rebind later authoring recipes to actual baseline preimages; do not replay
old full-source pins onto the frozen current-mod output.


### Capability-first source discovery (2026-10-19)

The user rejects migrating every historical script. Treat the 410-path corpus
as a discovery checklist; current bodies, resolved providers and qualified Git
history reveal shared mechanics versus patch data, obsolete repairs and tests.
`tools/rework/new_tool/maintenance/parity.py:analyze_sources` already supplies
static exact/parameterized AST clone ranking; reuse it rather than writing a
second analyzer. Its fingerprints preserve names/calls/lookup keys/operators and
literal relationships. Candidates are review leads, never safe-merge or savings
proof. Lexical Python token counts are not model-token counts.

Partition all current source paths once, pin their bytes, and keep per-script
capability/role/evidence/exception/unknown records. Independently verify exact
union membership and hashes. Follow compatibility providers; inspect historical
refusal bodies where needed, explicitly distinguishing hash-matching baselines
from differing historical references. Keep runtime ownership and exact-control
comparison separate from generic process teardown or markup-stripped equality.
See `tools/go/analysis/reusable-toolkit-plan.json` and its verification receipt.
The first authoring target is a narrow read-only fit proof using existing codecs
and native facts without placement/approved-target requirements. Keep strict
patch planning/writing intact; choose boundaries by responsibility, not old script
names or a fixed function count. No authoring implementation follows merely from
the completed static crawl.


### Read-only native authoring fit and live baseline drift (2026-10-19)

`tools/go --fit-profile` composes existing encode/controls/inspect/wrapPages
without patch destinations, complete references or preapproved encoded hashes.
Fit profiles own source/font pins, consumer limits and registry ID selections;
wording stays in the registry and generated hashes remain report evidence. Keep
this purpose-specific schema separate from writable recipes. `--apply`, output
and recipe flags must fail before entering any writer. Native font inspection
shares one metric block and must not fabricate loader/allocation readiness.

Measured wrapping reuses the same atom/page algorithm with native advances; nil
advances preserve the historical character policy. Count space width, keep long
words intact for overflow diagnostics, and refuse unmodeled substitution/scale/
position. No-page consumers retain wrapped lines on the same page and report
excess rows. Paged consumers may promote a LINE block into a new page. Count
blank lines/pages even before content; a blank-only stream still has one row.
Native pen bounds do not prove ink containment, visual row pitch or gameplay.

Separate whole-image identity from unchanged measurement facts. A live source
pin mismatch correctly refuses even when font pages match. Read-only full-image
delta can map changes to named ISO files and explain them through the current
planner; translation-blob addresses use sentinel mapping, not the old native
ELF delta. Never silently repin a baseline. Purpose-grouped profiles demonstrated
three new-wording dialogue cases and78 canonical item descriptions with no
consumer-specific functions. See tools/go/evidence/fit-* and the live-vs-frozen
analysis; compiler snapshots still do not replace semantic authoring duties.


### Bounded numeric wrapping and standalone texture authoring (2026-10-19)

Native wrapping now delegates every atom to the existing controls scanner;
consume numeric bounds in source order, including across LINE/PAGE. Keep one
width/sign/domain implementation, refuse missing/unused/null bounds and do not
split long substitutions. See tools/go/evidence/numeric-wrap-proof.json.

For fixed-palette TXDs, tools/go --texture-profile uses one bounded RW/GS codec,
Go PNG and an exclusive standalone output. Shared readInput serves text and
textures; keep UTF-8/hash semantics at their respective boundaries. Export a
pinned selector, edit externally, then import a pinned PNG with optional allowed
rectangle union. Retain original indices where colors match, original raw CLUT
alpha, metadata and bytes outside changed pixels. Quantization uses historical
integer alpha-weighted distance and first-index ties, not Go Palette.Index.
No archive-specific writer or handler per texture. Fail closed on unknown
packets, depth, dimensions, palette modes and mipmaps. The initial strict codec
matches148 corpus rasters; two nonzero CLUT upload positions are deliberately
unsupported. Standalone readback never grants ISO/art/gameplay approval.

Check primary flags, rather than inferring enum values from one asset: librw
[raster definitions](https://github.com/aap/librw/blob/master/src/rwobjects.h)
and [PS2 implementation](https://github.com/aap/librw/blob/master/src/ps2/ps2raster.cpp)
place AUTOMIPMAP at0x1000, PAL8 at0x2000, PAL4 at0x4000 and MIPMAP at0x8000.
Read rasterFormat as uint16 at0x0c and native version as uint16 at0x0e;
0x10000 in the old combined uint32 was version1, not a raster flag. Require calibrated80-byte GS
upload packet words, not just total lengths. Corpus/oracle and malformed-output
refusal receipts live in tools/go/evidence/texture-codec-* and
analysis/asset-codec-parity-final.json. The source version is pinned; later
codec enhancements need their own evidence rather than rewriting old proofs.


### Calibrated PSMT4 through the existing texture operation (2026-10-19)

The same texture/authorTexture handles all74 village plates:128×32/TBW2,
PSM0x14, rasterFormat0x4504/version2, palette base28 blocks and TEX1LOW0.
The old combined uint64 called TEX1 actually joined paletteOffset and TEX1LOW;
its0x1c was a palette base, not MXL7. Check TEX1LOW at0x1c directly. The4-bit palette has16 entries/64B,
but the packet uploads96B (8×3), including32 immutable0xcd bytes. Pixel upload
is64×16/2048B. Exact GS packets, source pins and selected layout remain guarded.
A derived composed bit mapping replaces copied GS lookup tables only for this
geometry; independent4096-entry GS-table-join fixture validates actual decoding
with three nibble-digit ramps. Read the current artifact byte when changing a
nibble, or the second edit can undo the first. Never quantize against256 entries
when only16 exist. Reuse masks, quantizer, publisher and profile schema.

Root224-raster differential gives222 exact accepted and2held. Independentall74
eight-pixel edits include58 actual double-nibble witnesses;27 malformed variants
refuse output. Real standalone4-bit PNG/TXD no-op also passes. See
analysis/psmt4-reuse-contract.json, analysis/indexed-texture-parity.json and
evidence/psmt4-codec-proof.json. Other4-bit geometry/raw32 remains unsupported;
this is offline byte parity, not new rendered-art approval.


### Scale evidence is not permission to multiply widths (2026-10-19)

analysis/native-scale-reuse-contract.json pins17 native MIPS blocks from the
current executable. E8 scale is absolute payload/100; E864 sets1 rather than
restoring prior state. SPACE uses14×scale, while glyph motion separately
subtracts scaled bearing then adds scaled advance. Those float operations do
not exactly equal multiplying the existing integer advance. LINE/PAGE alignment
lookahead may execute future controls, and per-word zero-based scans lose state.
Even a stable leading scale needs a declared consumer origin/alignment, unit
budget and numerical/native-FPU composition bound before an acceptance claim.
Do not add a nominal model or silently reinterpret existing398/530 native-unit
profiles as screen pixels. Current comparison prefixes at2f0750/2f0adc are70%,
not the historical80%; these are separate from item-description policy.
Scale-enabled acceptance remains held; no new state engine was added.

The same unscaled fit operation also checks27 Job Center summaries using a
400-unit/3-row/no-PAGE profile, with no new code or copied English. Independent
job-center-fit-review verifies canonical IDs, encoding, actual metric pages and
all widths (maximum396). This read-only layout proof excludes original stream,
slot capacity, references and visual acceptance.


### Monochrome font atlas through the same raster operation (2026-10-19)

Three currentfont pages are512×512/depth32/headerless RF0x504, TEX0=0x664020000,
TEX1=0,64Binfo/1MiBlinear pixels/noCLUT. Require exact mode, grayscaleRGB and
rawalpha0..128; do not infer coloredRGBA/BGRA from grayscale lineage. Export
min(255,2×rawalpha); keep original4B pixel on unchangedRGBA. Changed grayscale
pixels use rawA=(candidateA+1)//2, the existingCLUTencoder's half-up rule.
Hash/report the decoded result, not arbitrary candidate opacity. A changed
pixel outside masks refuses even when rounding would yield unchanged bytes.
Mode is generically import_png, not a false fixed-palette label for directfonts.
Same parser/walk/masks/publisher/profile, no newfunction/CLI/schema/dependency.

All3 actualpages no-op exactly,256candidatealphas/129native inverses/hiddenRGB
and malformed safe refusals pass. Root227 corpus gives225accepted/2held; proof
raw-font-codec-proof.json. font2 differs from historicalrawPNG by exactly25
known apostrophe-donor pixels; do not repin it to stalePNG. Atlas edits do not
update metrics or approve glyph-neighbor/alias/rendering suitability. Preserve
other pages, metadata, sourcefiles and alreadyapprovedart.


### Existing-ID human wording through the shared registry transaction (2026-10-19)

Use registry_author for en/note only, with exactly the six documented recipe
fields, pinned source and explicit date. Changed English requires drafted or
zone_pending; notes and same-value English preserve locked entries. Validate
selected OLD English as well as new text before comparing: Go's JSON decoder
can replace a lone surrogate with U+FFFD, making malformed old text falsely equal
to valid replacement text. Reuse the quoted JSON walker for this check and for
duplicate rewritten keys; nested opaque values remain raw. Reuse the existing
exclusive writer/readback, never write the canonical registry. Proof
registry-author-proof.json records synthetic new-snapshot containment and reuse
by fit preview; this is not a new-row/full-import/85-caller replacement.


### Native texture metadata correction (2026-10-19)

Use the64-byte StreamRasterExt layout: RF uint16 at0x0c, native version uint16
at0x0e, palette base uint32 at0x18 and TEX1LOW uint32 at0x1c. Version2 means
standard packets; version1 is the calibrated8-bit headerless variant, version0
the direct font mode. Exact known RF/version/palette-base combinations and
TEX1LOW0 refuse unsupported formats and mipmaps. Earlier uint32RF and uint64
TEX1 labels combined separate fields; their valid-input byte goldens remain
factual, but do not establish malformed-mode validation. The new
tools/go/evidence/texture-metadata-proof.json closes this with225exact corpus
cases and10 malformed CLI refusals. Never relax the two held nonzero CLUT
upload positions without the game's actual loader/CBP binding.


### Disk-backed regression workspace (2026-10-19)

The maintenance suite retains enough synthetic ISO fixtures to fill the16GB/tmp
RAM filesystem. Set an owned /var/tmp TMPDIR/GOTMPDIR for Go checks and an explicit
owned /var/tmp pytest --basetemp for broad Python runs. Preserve JUnit/logs outside
the fixture tree. If a run exhausts temporary space, stop only its recorded PID
and starttime/cmdline, classify failures, and remove only that run's generated
fixture tree. Do not clear shared /tmp, global caches or another probe's files.
An interrupted run is not a pass; stale historical-source assertions are distinct
from disk errors and must not be silently repinned.


### Calibrated native allocation footprint (2026-10-19)

Native info0x38 is total allocation in32-bit words, not bytes. Within current
calibrated modes, full128×64-page PSMT8 uses pixel_count/4+2048 words (palette
page included);128×32 PSMT4 reserves one2048-word page despite2048 pixel bytes;
512-square direct32 uses pixel_count words. Check exact stored size in the same
texture parser; reject partial-page8-bit layouts until calibrated. Proof
texture-footprint-proof.json records225exact/2held and48 malformed output
refusals. This is not a general GS allocator or native rendering proof.

### Source-selected native advance exception (2026-10-19)

Shared font inspection requires `unfloored_glyph_vma` and `unfloored_glyph` in
each Layout/font profile. Read and guard the source u16 before extracting advances;
only that full glyph ID bypasses the 22-unit floor. Keep the separate SPACE 14/24
override. Current source address is 0x478e5c, value 0x1b: comma advances 6 units,
not the earlier model's 20. The old scale study's 0x488e5c label was incorrect.
`tools/go/evidence/native-advance-exception-proof.json` verifies all 108 selected
fit rows and the relative-envelope refusal. Retain old reports as historical
outputs; this correction does not enable scale, positioning or nested strings.

### Native shared-base CLUT upload (2026-10-19)

For the calibrated standard 128×128 PSMT8/TBW2 mode, metadata palette base is
64 GS blocks. The game's registered v2/cache loader reuses the pixel BITBLTBUF;
palette TRXPOS must be (0,64), which matches sampled CBP=uploadBase+64. Keep pixel
TRXPOS zero and require zero for other calibrated layouts. Derive the expected
position in the existing packet loop; preserve exact register/count/direction,
metadata, allocation, palette and mask guards. Never accept arbitrary positions
or name specific assets. `tools/go/evidence/clut-packet-proof.json` verifies all
227 corpus rasters and malformed refusals. This is static normal-path evidence
and standalone editing, not arbitrary runtime callbacks or visual approval.


### Source-bound word restoration (2026-10-19)

Reverse independent native assignments with explicit reviewed preimages and
original target words in the existing `guarded_words` recipe. Bind source and
whole expected output. That initial increment required one word table; the
bounded-slot increment below supports explicit agreement across word/slot tables.
Keep planner/replan/exclusive copy/readback/hash/owned cleanup shared. Preview
reports the target pin but does not certify its digest. Fresh independent source
and virtual-image oracles precede any actual scratch apply. The F003 proof
`tools/go/evidence/reverse-word-proof.json` restores all predecessor bytes after
two fresh reviews. Never infer rollback of coupled text, pointers, allocation or
registry state from this independent-word case.


### Bounded terminated text slots (2026-10-19)

Use shared `stream_slot` for a fully reviewed old extent up to8192B, with an
active encoded SHA including END before padding. The scanner's Padded mode must
reach the existing default control allowlist before exact-token capture; require
zero-only tail. Preserve all supported non-break control words and absolute
offsets; only LINE/PAGE/END positions may move, never their order/count. No setup
or opaqueparam8 workaround. Composed word/slot output pins must explicitly agree
in every table. `tools/go/evidence/stream-slot-proof.json` verifies the synthetic
primitive; source, references, consumers and slot ownership need separate proof.


### 2026-10-20 — Canonical original wording in bounded Go slots

Use the existing `stream_slot` recipe's `wording_field: "jp"` to restore the
selected registry ID's canonical original wording. Empty selector retains EN;
unknown selectors and selectors on other operations refuse. JP stays raw JSON
until selected, so unrelated JP metadata does not tighten existing EN flows.
Clear the destination before JSON decoding: `null` must not inherit EN. The
selected string must be nonempty/UTF-8 and its encoded active bytes must match
the recipe pin before zero padding. Standard Go JSON escaped-surrogate replacement
remains; this is not a new strict scalar parser. The pinned real glyph map has no
replacement character, and the encoding pin still binds the exact allowed bytes.

Keep source/full-slot preimage/output identity in separate recipe data. Reuse
plan/encode/controls/validateEdits/verifySource/patchCopy, with CLI and independent
bundle/reference domain guards. The actual isolated native label restoration
(evidence in `tools/go/evidence/jp-selector-proof.json`) equals every original ISO
byte after two fresh reviews. Synthetic mixed18/290-byte cases prove transaction
composition, not historical145-word narration ownership, visual fit or automatic
undo. A later real copy still needs fresh reviews and full readback/containment.


### 2026-10-20 — Exact palettes through the existing Go codec

For standalone standard PSMT8 imports, opt in with `palette_policy: "exact"`.
Omitted policy preserves old raw CLUT alpha, duplicate indices and mask semantics.
Exact mode requires a whole candidate PNG and refuses rectangles/export/other
layouts/depths and257+normalized colors. Alpha rounds with integer `(A+1)/2`,
ties upward, displayed as `min(255,2*raw)`; transparent pixels become RGBA zero.
Sort normalized packed RGBA values, fill at most256logical entries and zero the
rest. Reuse the existing CSM1 physical-index loop to write CLUT bytes and the
existing pixel walk/index map to encode the raster. No approximate fallback.

Five m_015256-square source fixtures bind RF0x2504/version2/TBW4/paletteBase256/
18432allocationwords and unchanged packets. The normal native v2/cache path uses
separate pixel upload atB and CLUT upload atB+256; sampledCBP agrees. This differs
from the earlier128-square/TBW2 merged upload atY64. Source-dependent native facts
stay explicit; do not relax arbitrary packet positions or allocation sizes.
`tools/go/evidence/exact-palette-proof.json` binds five actual standalone imports,
227default preserve cases, full Go checks and ordinary review. It grants no ISO
alias/sharing safety, artwork/visual approval or full texture-family coverage.

Credential scan patterns should use POSIX `[[:space:]]` in `rg`, and self-check
against nonsecret sample assignments before scanning source. The earlier root/
review whitespace expressions had doubled backslashes; corrected scans retain
that history as superseded. A no-match exit alone does not prove a useful pattern.


### 2026-10-20 — Multipage PSMT4 without another mapping engine

The same depth4 codec now accepts two calibrated modes:128x32/TBW2/paletteBase28/
2048allocationwords and512x512/TBW8/paletteBase512/34816words. The latter uploads
PSMCT16 at256x256/DBW4 and samples PSMT4 at512x512/TBW8: both use4pages per row.
Sixteen pixel pages plus a reserved CLUT page explain its footprint. The normal
native path uploads the8x3CLUT separately atB+512 and samples CBP=B+512. Preserve
16color entries and32CD-padding bytes; the24transferred words are not a simple
linear VRAM interval. Do not loosen arbitrary dimensions or sampling fields.

Reuse the existing column/row/bank expression with width-based placement; the
full262144entry independent table join and old4096village map agree. Five frozen
RGBA address-digit ramps cover18physical nibble-address bits without embedding
another giant lookup table or repeating the new formula in tests. Preserve
read-modify-write against the current artifact byte when two logical pixels
share low/high nibbles. Corners/page-boundary/shared-byte full-artifact oracles
and actual standalone import/export are bound in
`tools/go/evidence/multipage-psmt4-proof.json`. Native layout equivalence is not
legacy non-village ISO/art approval, alias ownership or visual verification.


### 2026-10-20 — Colored direct pixels through the same codec

`tools/go` texture profiles can set `pixel_policy: "rgba"` only for the already
calibrated512x512 version0/headerless direct32 layout. Default mode retains
monochrome font source/candidate refusals. This policy and `palette_policy` are
mutually exclusive; the existing codec argument carries their one validated
choice. No options struct, helper, alternate pixel walk or writer is needed.

Native loader/GS proof binds straight packed R,G,B,A and source alpha0..128.
Preserve hidden RGB at alpha0; do not premultiply, unpremultiply or clear it.
Project PNG uses min(255,2*raw) and edits use (candidateA+1)/2 (ties upward).
Native GS blend uses alpha/128; PNG scaling is an authoring convention, not a
blend simulation. Source alpha>128 always refuses, including explicit rgba.
The actual NPC source/two-edit oracle, all256candidate alphas, same-rounded-byte
outside-mask refusal, output safety and old227default rasters are bound by
`tools/go/evidence/direct-rgba-proof.json`. Other finite direct layouts need
storage/stride/footprint proof; never add a fake empty CLUT packet to v2 direct.
No ISO/art/visual approval or workflow-family promotion follows from conversion.


### 2026-10-20 — Finite direct layouts without per-layout handlers

The existing `texture` depth32 owner now binds six observed native modes:
version0 512x512/256x512/512x256 and version2 256x256/128x16/16x16. All additional
modes require explicit `pixel_policy: "rgba"`, even monochrome/null sources;
default font scope remains512-square/version0. Keep exact TEX0/version guards.

Direct GS allocation is ceil(width/64)*ceil(height/32)*2048words, with minimum
TBW1. Small source rasters do not fill their reserved pages. Version2 direct
stores exactly one80-byte upload header plus width*height*4 bytes and zero CLUT
info; its packet uses full width/height. Indexed version2 keeps two headers and
its existing upload dimensions. Gate the indexed storage branch on depth!=32;
otherwise a fabricated empty CLUT header could pass. Slice the existing packet
list to one before direct validation; do not create a second checker/helper.

`tools/go/evidence/direct-layouts-proof.json` binds original full-member oracles,
native storage/stride/allocation, sibling containment and actual standalone CLI
checks. The field_map member has114 total textures,113 unselected siblings.
Same-map cancellation is proven only within declared logical bounds; native
filtering, out-of-range sampling, visual acceptance and ISO placement are separate.


### 2026-10-20 — Small PSMT8 CLUTs occupy page holes

The existing Go depth8 branch now calibrates version2 32x32/base28/2,048 words,
64x128/base60/4,096 words and64x256/base124/8,192 words. These exact TEX0/base
pairs use minimum TBW2; direct32 keeps minimum1. The standard indexed storage
still has two80-byte headers, full raw1,024-byte CLUT and no CLUT padding.
Palette uploads require X48 with Y16/48/112. Enhance the existing packet-position
fields to encode X32|Y48; keep every setup/count/register word exact.

These are unused page holes, not a contiguous prefix plus an extra CLUT page.
Native game geometry tables are indexed by depth-1: depth8 at0x5169bc/0x516a3c
is128x64, distinct from direct32 at0x516a1c/0x516a9c (64x32). Prove upload
PSMCT32/samplePSMT8 byte addresses by independent GS table joins; same-map
cancellation from direct32 does not apply across these different formats.

`tools/go/evidence/small-psmt8-proof.json` binds all four original rasters and
independent preserve/edit/exact oracles. Exact policy retains sorted normalized
RGBA, ties-up native alpha, transparent RGB0 and zero-filled unused palette.
Source e01 has27 total textures; preserve26 unselected siblings. Existing test
owners must use actual image width for257-color and256-alpha vectors instead
of assuming width256. Other small/headerless/mipmap modes and approximate
quantization remain held until their own facts and tests; no ISO/art approval.


### 2026-10-20 — Group partial-page PSMT8 facts before adding cases

`tools/go` now uses19 finite dimension pairs and one page/base formula for
partial-page version2 PSMT8. Clear only TEX0 TBW/TW/TH for its native-core check
(0x2000000401300000); common guards bind those dimensions and buffer width.
Allocation is ceil(w/128)*ceil(h/64)*2048 words, palette base=allocation/64-4.
TBW2 uses merged CLUT X48,Yallocation/64-16; wider formats use separate CLUT
DBP=B+base with X/Y0. Keep the old full-page/headerless branch and its meaningful
flag allowances. Do not expand arbitrary geometry merely because a formula fits.

`tools/go/evidence/grouped-psmt8-proof.json` binds16 new actual representatives,
independent native/GS and preserve/exact oracles, current227/default+21direct
regressions, source/sibling containment, mutation and publisher tests. Reuse
existing field-map data for11 groups and append three source members plus16 PNGs
to the existing fixture ZIP; no additional archive/loader/hash field is needed.
For16x16,257 unique colors are impossible: cap that vector by pixel capacity.
A negative packet vector must change input; wider CLUTs legitimately have zero
position. Retain pure X/Y mutations instead of calling an unchanged zero invalid.

Pure adversarial Astra026 found no actionable issue; its focused test/accounting
checks are not ISO approval. Runtime grows341 bytes, tests392, fixtures701,725;
no new function/type/argument/policy/schema/import/writer/file and no reduction
or family credit. Original PSMT4 census is75 records in the two existing modes,
not a queue of arbitrary future geometry authoring. Below16 crop/padding and
original approximate-palette caller responsibilities remain separately tracked.


### 2026-10-20 — Share exact and approximate palette generation

`tools/go/texture_palette.go` owns normalization, the histogram, sorted unique
colors and logical indices for both exact and quantize policies. The pure owner
absorbs the prior exact block. Keep native TXD parsing, GS mapping, CSM1 writes
and publication in their existing owners. Adding a numerical algorithm inline
to the already large codec would hide independent invariants; this justified
one function, rather than a helper family or per-image handlers.

The reference uses unweighted unique-color variance multiplied by pixel
frequency, stable channel/box ties, weighted median cuts, exactly eight weighted
Lloyd updates, retained empty clusters and final assignment before ties-even
rounding. Preserve mode has a different distance metric and cache bound; it
cannot supply approximate assignments. Nontransparent normalized alpha is at
least2, so the reserved transparent entry can stay first without merging rounded
palette duplicates. Exact still refuses more than256 normalized colors.

`tools/go/evidence/approximate-palette-proof.json` records seven canonical whole
TXD/CLUT/pixel/RGBA cases, the227-case regression corpus, actual CLI safety and
numerical mutant checks. Reuse the real image/source in the existing ZIP; append
only six synthetic PNGs. Root and independent full race/vet/build/format/scans
pass. Cost:5,593 production bytes/one function/file,571 test bytes and16,465
fixture bytes separately. This is capability growth, not source reduction.
Seeded row counts are not unique-color counts: measure normalized RGBA rather
than infer it from generator size. Floating parity remains bounded to tested
cases. Two original full-page CLUT positions remain a separate concrete gap;
no family, retirement, ISO, art or visual approval is implied.


### 2026-10-20 — Bind full-page TBW2 CLUT positions by guarded base

The original exporter positively supported128x64 and128x256; the Go packet
validator had only special-cased128square. The existing condition now covers
finite heights64/128/256 and derives Y from the already checked palette base.
For these full pages, base32/64/128 has low five bits zero and the native inverse
block permutation leaves it unchanged: X0,Y=base=height/2. Keep the19 partial-page
rules separate and do not infer unobserved128x512/1024 palette positions.

`tools/go/evidence/fullpage-tbw2-proof.json` records both actual source/no-op/
four-corner/exact/CLI cases, native18-span/10-primary and all pixel/CLUT joins,
26 siblings, alpha/limits/idempotence/publication and coherent refusals. Prior
full-page TBP/TCC/TFX flag allowances remain meaningful; do not apply strict
partial-mode mutation expectations to them. Root race57.806s and independent
88.484s with227 previous cases plus required checks pass. Reuse the existing
e01 source and append only two exact PNGs. Cost51 production bytes,59 test bytes,
5518 fixture bytes; no new function/type/argument/policy/import/writer/file or
runtime bundle. Two representatives are not299 independently executed exports.
The same-baseline family assessment remains a separate completion check.


### 2026-10-20 — Complete a family against its original contract

`tools/go/analysis/texture-codec-final-assessment.json` independently crosswalks
seven original codec duties to source callers, shared Go owners and accepted
proofs. Approximate generation and full-page positions close the two concrete
gaps. A targeted actual256x64 export/no-op/native check resolves the last
representative question. Below16 has affirmative original parser/export refusals;
do not infer refusal scope from absence of authoring callers alone.

Root accepted texture_codec as Full against the unchanged baseline. Core coverage
is4/14=28.57% (8 partial,2 unsupported), expanded4/17=23.53%. Rendering/TTF/resize,
preview/inventory orchestration, placement, visuals/art and historical caller
retirement are separate contracts. Full does not mean all possible PS2 formats,
arbitrary floating histograms or every asset row was exhaustively tested.

### Shared binary-font cell rendering (2026-10-20)

`tools/go` texture profiles can now provide an inline `render` recipe with pinned
shared font JSON/GrayPNG and separate cells. `composeCells` owns the finite binary
font layout, outline/shade and replacement pixels; `authorTexture` retains input
pins and orchestration, then reuses the codec, cell-derived mask and exclusive
publisher. Keep numeric color arrays readable; Go byte slices serialize as base64.
Whole-cell Src and opaque ink copies preserve hidden transparent-white RGB.
The five HUD cells reproduce the approved whole TXD and raw RGBA from ORIGINAL
source, not from the already-translated bundled target. Proof:
`tools/go/evidence/bitmap-render-proof.json`; independent review verifies all227
prior cases and refusal/publication safety. Production+data grows12,694B, tests
and fixtures separate; no savings or retirement. Raster rendering is Partial;
core4/14=28.57% now has9partial/1unsupported. Native AA, fit/styled runs, TTF and
donor reconstruction remain separate unverified responsibilities. No ISO, visual
or gameplay approval follows.

### Native-font resampling foundation (2026-10-20)

Use the existing `tools/go/resizeRaster` for full-image Gray/NRGBA LANCZOS.
It preserves the pinned Pillow12.3 numerical contract: identity before alpha
conversion, signedQ22 coefficients, clipped byte intermediates, skipped unchanged
axes, the tall-image V-first case and floor unpremultiplication. Alpha0 retains
already-filtered RGB. Source/output/intermediate bounds and storage validate
before allocation; source stride/origin are preserved and output is fresh at0.
Proof `tools/go/evidence/raster-resize-proof.json` binds134 pixel vectors and8,803
coefficients/1,362 starts, independent race/regression and four numerical mutants.
Reuse this owner in glyph/word stages; do not duplicate its kernel or add filters.
Required notice `tools/go/licenses/Pillow.txt` is counted with code. Native-font
caller integration remains incomplete; this adds no family credit or retirement.


### Native optical runs through existing Go texture authoring (2026-10-20)

Use the existing texture profile with a shared font descriptor/Gray atlas and
separate run/cell layout data. composeCells retains common preflight, backgrounds,
unclipped-alpha containment and final placement. renderRuns owns bounded native
metrics, quarter-step fit, masks/counters/stroke and supersampled area; pixelOver
shares the exact Pillow integer formula in glyph and final composition contexts.
Reuse resizeRaster for glyph and word stages. Keep per-run advance summation order,
lowest-X/then-Y nearest-color ties, four-connected counters and rounding before
base-image origin addition. Standard draw.Over changes hidden RGB/rounding.

Proof tools/go/evidence/native-text-proof.json binds actual original mini_g01
source, whole TXD/raw candidate/decoded RGBA and5,371 contained changes. Independent
counter fixtures catch eight-connected fill; do not derive expected data from Go.
Active render profile/font documents reject null rather than silently accept zero.
One small glyph-colored stroke style is verified; other native styles, TTF and
full-card/donor reconstruction remain incomplete. Raster stays Partial; no ISO,
visual/gameplay, retirement or reduction claim. Runtime cost36,712B includes
shared font/profile data; tests/fixtures are separate.

### Native style reuse and original background preservation (2026-10-20)

Use existing renderRuns for the four observed native tracking/ordered stroke
styles. Explicit outline role preserves named-outline semantics independently of
RGB. Keep ONE float32 BitmapLayer until caller composition; early rounding changes
real native indices. composeCells owns float versus Pillow final composition.
Keep approved Rect, BackgroundRect and fitting bounds distinct: enlarging an ink
mask must not expand background paint. Outside paint, both compositors use the
original sourceRGBA, including transparent hiddenRGB. Source texture policy first
snaps to lexicographically ordered used-sourceRGBA, then runs the existing full
native-order integer distance selection; exact-index shortcuts break alpha ties.
Raw mask checks precede projection; projected equality preserves duplicate indices.
Source cache bounds storage, not accepted color count. No new function/writer.
Proof tools/go/evidence/native-styles-proof.json restores original tutorial8931937b
and6,411 contained changes. Four styles are not113 operations or full raster
coverage. Runtime11,091B growth, tests/fixtures separate; no ISO/retirement claim.

### Shared native line groups (2026-10-20)

Use optional group data in the existing texture renderer. composeCells owns
shared width/height fit, original leading ratio and ordered per-line byte
composition. renderRuns stays the sole style/raster owner and returns selected
size/work metadata; rerender at final anchors instead of moving rounded probes.
Keep fit box, approved Rect and BackgroundRect separate. Minimum-size estimates
may overflow; actual ink containment still refuses spills. Shared layout uses
center/left alignment; group data uses middle/top. No new helper or writer.
Proof tools/go/evidence/native-line-groups-proof.json matches eight independent
candidates and original help01 whole6dcabbb1/11,735 native changes. Focused tests
and ordinary review pass; full integrated/race suite deferred by user direction.
Prioritize the remaining reasonable toolkit foundation (snapshots) before more
rendering edge cases. No full-family, retirement, ISO or gameplay claim.

### Opaque artifact snapshots and streaming publication (2026-10-20)

Use --snapshot create/list/restore with explicit snapshot directory and source/tag
or new restore output. snapshotArtifacts owns tag/receipt lifecycle; do not route
opaque snapshots through fake patch recipes or registry inputs. writeNewFile now
accepts a Reader plus mandatory expected size/SHA256, hashes the copy and rereads
the destination with bounded memory. Registry/texture callers adapt their known
bytes to Readers. readInput owns bounded receipt reads. Receipt LAST marks
completion; fixed filenames and exclusive tags avoid mutable-index ambiguity.
Failed create can leave an incomplete reserved directory; never RemoveAll unknown
paths. Restore prehashes and writes only a new file; inventory does not hash.
Caller-supplied commit does not prove clean source or trigger checkout. Create
and restore apply each require roughly3 payload passes. Proof
tools/go/evidence/snapshots-proof.json binds focused root/ordinary CLI checks;
full integrated/race suite deferred. All14 areas now have scoped entry points,
not full family contracts. Preserve legacy ledger/audits; no ISO/runtime claim.

### Registry document ownership boundary (2026-10-20)

Use existing authorRegistry for author/merge/markup/text-shape document operations.
run selects recipes, validates the source handle and routes normalized
RegistryOptions; it retains source-close ownership. authorRegistry closes only
its separately opened derived registry source. Preserve raw JSON unknown metadata,
exact numbers, human/machine field policy and refusal order. controls retains
text semantics and writeNewFile retains publication. Mechanical extraction from
run preserves all482 original body lines under four explicit value substitutions;
proof tools/go/evidence/registry-owner-proof.json binds independent equivalence
and full uncached Go race145.271s/build/vet/format/scans. This adds568B boundary
overhead, not code reduction. Use the14-area owner map before extending a workflow;
all14 scoped entrypoints do not imply complete historical coverage.

### Exact menu LINE contracts in the shared fit preview (2026-10-21)

Use optional FitBox.required_line_breaks when a proved consumer depends on exact
LINE controls, including trailing breaks. Explicit0 differs from absent/null.
previewFit sums len(page)-1 from existing controls.LineWidths; PAGE is separate.
Constrained boxes refuse automatic wrapping, which could alter menu options.
Successful measurements expose line_breaks; unsupported scale/encoding stays
unknown. row_count_mismatch retains existing overflow diagnostics. Profile duplicate
keys and aliases of this field refuse. Two frozen native menu entries demonstrate
3LINEs versus4penrows; these loose bounds do not prove physical geometry.
No extra scanner/helper or family promotion. See tools/go/evidence/fit-line-count-proof.json.

### Exact authored-asset joins without a new executor (2026-10-21)

Use the existing --texture-profile entrypoint with operation specification and a
separate specifications map keyed stableassetID. Each row selects one exactunique
native name and optional authored category/wording/context facts. authorTexture
shares indexTextures.byName with the codec; duplicate names remain visible and
missing/ambiguous/repeated selections refuse. Output retains source ordinal and
separates parsedheaders from measured decodedsize/RGBAhash. Unknown decode stays
null/diagnostic. SourceSHA/size verified; archive/member/context are declaredlabels,
not newlyproved placement or screencontext. No apply/output or canonicalwrites.

This satisfies the authoredjoin/geometry duty only after its independent checks.
The explainer_scan detector, tier and flag roles are MATERIAL later manifest
duties; do not call them optional or infer them from image dimensions. Same-root
documentation example uses examples/asset-specification/source.txd + profile.json.


### Stream batch discovery through shared codecs (2026-10-21)

For extracted CMB inventories use the existing --texture-profile operation manifest,
with full source size/SHA and index_sha256. cmbIndex retains original index order
independently of physical payload order; existing replacement planning shares it.
manifestTextures accounts for every entry/native/error, joins authored IDs on exact
entry+texture, and packages PNGs plus manifest in one exclusive verified ZIP via
writeNewFile. Numeric preview paths avoid source-name collisions/traversal. Hash
and identity checks precede publication; no ISO or canonical writes are involved.

inspectRaster owns source-backed advisory tile counters/tier/ordered flags without
changing pixels. Keep <8 and nonmultiple8 score domains unavailable: original code
returns an invalid short tuple or throws a cropped-mask exception. Folder/name
hints on decoded images remain separate from those missing measurements; no
pixels means no reasons. These are discovery leads, not OCR/visual approval.
Potential failed decodes count toward the work budget. Preserve budget/error rows;
never truncate entry accounting. Checkerboard/contact duties remain separate.

Raw PNG exports keep encoded source bytes exactly; discovery/RGBA hashes follow
pinned Pillow12.3 conversion. Gray16 clamps raw values to255; gray/RGB tRNS
comparison occurs after conversion, with low-byte keys and the special1-bit rule.
Preserve straight hidden RGB for palette/NRGBA64 samples. Independent34type
oracles are in tools/go/analysis/asset-png-conversion-contract.json; do not replace
this path with draw.Draw or generic premultiplied color conversion.


### Reuse actual parsed TXD context, not just lookup code (2026-10-21)

Batch/specification callers pass their existing TextureIndex to texture. The
optional prepared index is an INTERNAL read-only view bound to the exact source
slice start and length; caller must not mutate either index or bytes while used.
It is not a cryptographic cache and must never be reused for a new member, equal
content copy or newly encoded artifact. Nil retains standalone parsing; artifact
readback stays fresh. This avoids N+1 whole-dictionary parses per N native rows
without another parser/helper or global cache. Preserve duplicate-name and local
metadata error precedence. Ordinary review and proof govern closure, not Astra.

### Preview nearest sampling through the existing resampler (2026-10-21)

`resizeRaster` now requires an explicit filter. Existing font/run rendering uses
`lanczos` with no crop, retaining the 1M-pixel source/output/intermediate bounds.
`nearest` copies straight Gray/NRGBA bytes and preserves hidden RGB. Its optional
crop is relative to the source content origin, independent of Rect.Min; pixels
outside the source are zero before resampling. Crop views remain bounded to 1M
pixels / 4096 per axis, and preview output to 16M pixels / 16384 per axis. It does
not allocate a padded source. Pair assembly still needs its own combined budget.

Pillow 12.3 computes a binary64 step, starts at step/2, and adds step once per
output position on each axis. Keep that recurrence: source2→target7 maps0000111.
Rational center sampling or recomputing coordinates by multiplication changes
real output pixels. Full original-only oracles and the finite 131072-pair digest
are in `tools/go/testdata/raster-nearest.zip`; existing134LANCZOS cases stay pinned.
This is a numerical foundation, not completed checkerboards or contact sheets.

### Shared checkerboard comparison profiles (2026-10-21)

Use the existing texture entry point with `operation: "comparison"`, pinned before
PNG source, pinned `png` after file, evidence and `preview: {"scale": 3}`. Optional
`preview.crop` is XYWH shared by both images; positive out-of-bounds areas pad
transparent. Before cropped geometry controls both target sizes; an unequal after
image stretches independently. `resizeRaster` owns exact nearest sampling and
`pixelOver` owns integer alpha-over. Checker tiles are8 output pixels, gray150/200,
and restart separately for each panel; gap is6 output pixels on gray40. All output
pixels are opaque and the PNG is RGB. This does not alter source transparency.

`decodePNG` is extracted from manifest discovery and shared by these operations.
Keep Pillow12.3 conversion: Gray16 clamp, other16-bit channel truncation, tRNS
comparison after conversion and hidden RGB retention. Bounded valid headers charge
attempted work even if payload decoding fails; budget refusals/invalid configs
charge zero. Manifest keeps its existing per-row budget diagnostic and encoded
raw PNG bytes. Font coverage/native import decoders retain their distinct types.

Comparison profiles own their complete JSON schema and reject null numeric values,
duplicates, aliases and unrelated native authoring fields. Existing JSON callers
retain their null policy. Source/crop1Mpx, each nearest panel16Mpx, combined32Mpx,
output128MiB; normal512²@3x and1024x512@3x are supported. Recheck source/candidate/
profile bytes before exclusive publication through writeNewFile. Dryrun returns
hashes without an output. Source aliases can be read; output aliases/existing
paths refuse. Contacts and flat90/gap4scaled/RGBA variants are still separate duties.


### Labelled inventories through one collection pipeline (2026-10-21)

The Go texture entry point accepts `operation: "contacts"` over pinned manifest
ZIPs. `contacts.font` pins exact TTF bytes; optional `contacts.sources` adds pinned
bundles in declared order. It preserves empty/failed entry rows, metadata versus
decoded geometry, unavailable scores and existing PNG bytes. Inventory flags and
scores are supplied source facts; this operation does not rerun OCR or approve art.

Collect before grouping. Keep UI duplicates. In other groups remove duplicate
pixel keys BEFORE archive/index sorting, separately per group; later groups may
overwrite a preview's page link. CSV propagation is a distinct final pass using
the first linked key in source order. The original key is SHA1(rawRGBA)[:12], with
no geometry, so equal bytes at different dimensions still collide. Integrity uses
full SHA256 separately. Missing/empty source pixel hashes never deduplicate.

Cache measurement by exact source ordinal/member, not a row's optional hash.
Validate each row against those measurements, including rows that share previews
but differ in deduplication policy. Cache thumbnails on first use and bound their
aggregate pixels. Preserve per-row errors; never truncate inventory to meet bounds.
Recheck bundles/font/profile and publish only through existing exclusive writer.

Format each complete caption before splitting LF, preserving blank/trailing lines,
its original ink and line step `getbbox("A").bottom + 4`. Shape in bounded batches,
but paint each thumbnail followed by its caption masks before the next item.
Combining marks and multiline labels may cross cell boundaries: a later opaque
thumbnail must cover earlier ink. Whole-page clipping is deliberate; batching all
thumbnails before all labels changes pixels. Keep control and seven-item overlap
oracles together so a fix cannot erase the overflowing ink to make the case pass.
Source canonical-key depths are root1,entry3,raster5,nested6,score7; sources[] pin
objects in the profile are depth4 because arrays contribute depth.

The optional Linux `nativefonts` CGO build supplies one whole-label `textMasks`
backend using installed FreeType/Raqm APIs. It uses unhinted RAQM advances with
hinted final masks, BASIC's historical rounded-pixel kerning quirk, default ascender
bearings and two bitmap passes. The fallback declaration refuses contacts; it
keeps every existing command buildable without native libraries. Do not substitute
per-label images, BASIC for RAQM, native bitmap atlases or a Python runtime bridge.
Count both declarations, API header, font bytes, notices and build dependencies.

Grid facts belong in profiles/previews/inventory-layout.json. Patch recipes have a
different schema, enforced by runtime-table goldens. Existing resizeRaster owns
thumbnail-nearest/thumbnail-lanczos sizing: no enlargement, floor/ceil candidates
chosen by aspect-ratio error, floor on ties. Contacts chooses the pixel-art threshold
from the table; existing filters/crop limits retain their prior behavior.

The isolated font proof and ordinary integration review remain distinct from .06
promotion. Sixteen complete inventory-page oracles, original link/order/pagination/LF/overlap
cases, focused build/race/refusal checks and a runnable synthetic example cover
this increment. Captioned weekday pairs and flat90/source-gap4-scaled/RGBA remain
open. Full-family and410-responsibility migration claims require their own evidence.


### Keep pair layouts on the shared comparison path (2026-10-21)

Enhance authorTexture rather than adding a handler for each historical preview.
The separate pair-layout table holds backgrounds, gaps, captions, geometry, font
layout and PNG mode. Checker remains the default, with unchanged reports and
output-space checker/gap behavior. Flat uses a common XYWH crop (translate original
XYXY explicitly), transparent OOB padding for both inputs and a source-space gap
of four pixels. Integer-nearest scaled panels plus the scaled gap match the
original whole-canvas outputs, including 512²/1024×512 at 3×, without widening
the resampler's 1M source bound. Weekday paints labels then source strips at native
size on its fixed page, then scales the complete page; BASIC and RAQM cannot be
substituted silently. A pinned RegistryInput owns the exact Aileron font bytes.

Go's PNG encoder asks Opaque() before choosing RGB/RGBA. The narrow rgbaPNG type
returns false only at the flat encoding site to retain the original RGBA header,
even with fully opaque pixels; it does not alter alpha values. Count its method
and type, font/notice/table/examples and external native dependencies. No bespoke
PNG writer or new font/backend helper is needed. Test headers as well as full
pixels, guard refusals, all input rechecks and exclusive publication.

A family-level source audit found that a missing numeric detector score must not
automatically hide a decoded contact preview. Original _score_safe can return a
negative presentation sentinel while retaining the image. Keep actual measurement
unknown; distinguish missing detector records from evaluated failures before
closing the contact duty. This newly identified gap remains open at this pair
increment, so it earns no .06 or full-family credit.


### 2026-10-21 — Detector presence is distinct from score availability

Original explainer_scan keeps six-field detector-error results in contact groups;
missing detector records are a separate case. In Go, contactSheets consumes
explicit measured/unavailable/not_evaluated status and keeps unknown scores null.
Use -1 glyph/0 line only as evaluated-failure presentation. Preserve existing
pixel-duplicate link propagation, which can link a missing-detector row without
claiming it was measured. Test whole four-group pages plus a missing-record
control. For headerless PNG views, retain null native Header and use measured
dimensions/depth0; document canonical JSON/status/ZIP-path/LF differences.
[Proof](../tools/go/evidence/asset-contact-score-policy-proof.json),
[source closure](../tools/go/analysis/asset-preview-family-closure.json) and
[independent review](../tools/go/evidence/asset-contact-score-policy-review.json).


### 2026-10-21 — Inline icons share fitted runs and immutable composition

Declare same-sheet original source rectangles once in render.icons; icon runs
reserve fixed output-pixel widths plus explicit gap, independent of text scaling.
Preserve icon-only source measure/render-width tracking discrepancy and round
the word origin before icon coordinates. composeCells validates entire source
and approved destination rectangles, including transparent pixels, then copies
original RGBA after each line before the next line paints. Use Src replacement,
not blending or resized icons. Shifted image origins are added once. Frozen
[proof](../tools/go/evidence/inline-icons-proof.json) covers11originalRGBAcases;
three normalized group colours were corrected from white to the original default
black after independent replay, without changing expected pixels. Native codec
projection is not an independent encoder or actualTTFart parity claim.


### Shared pinned TrueType authoring (2026-10-21)

`tools/go` now accepts a shared RasterFont manifest with a bounded `truetype`
path/size/SHA256 source and BASIC/RAQM layout. Paths resolve from the font
manifest, itself relative to the texture profile. Use `-tags nativefonts` on
Linux/CGO; the default build refuses this operation. Exact Noto font/OFL data
and the tutorial op8 example are separate files, not per-patch Go handlers.

Keep raw whole-run measurement separate from tracked character painting.
Implicit LF at zero tracking paints repeated baselines into the same prestyle
canvas: default-anchor A bbox bottom plus Pillow spacing4. At nonzero tracking,
LF paints nothing but consumes its raw character advance and tracking. Explicit
line groups compose later and cannot substitute for this stage. Source ImageDraw
clips extreme combining marks to a fixed temporary canvas; final word-layer ink
still must fit the approved cell. Omitted background preserves input pixels;
explicit strokes[] means no TrueType strokes and must survive JSON round trips.

The proof `tools/go/evidence/truetype-raster-proof.json` records whole original
images and old accepted codec projection, not an independent encoder, arbitrary
Unicode/library-version equivalence or artwork/gameplay approval. No new
function; all code+font/notice/profile growth is counted. Raster5/6,65/84planning,
core6/14 Full unchanged. Full integrated suite/gameplay remain deferred.


### Ordered current-pixel reconstruction (2026-10-21)

Use the shared RasterComposition facts and separate
`tools/go/profiles/textures/help00-reconstruction.json` example; donor-only runs
need no font/backend. Allow is positive union minus exclusions then additions.
Mixed erases/text require exact unique-ID order; reads use current pixels except
icons, which retain original sources. Per-text permissions compare final changed
RGBA bytes before the next operation; raw fractional ink alone is not a leak.

Row/column donors complement the final limited hole inside the operation crop.
Grow four-neighbor selections before reapplying permissions; retain straight
RGBA/hidden RGB, ties-even interpolation, endpoint clamps and unchanged donorless
lines. Empty selections bypass method/fill validation. Native rectangles remain
coarse guards: independently compare native/readback bytes outside the exact mask.
Use existing checkJSON separately on owned objects so Unicode/case aliases refuse
without restricting dynamic icon IDs. Default order must allocate its own storage.

`tools/go/evidence/reconstruction-row-proof.json` binds focused native/core/race
and original images plus OLD accepted codec projection, not independent encoder
or visual/fullfamily approval. One justified numerical function; other masks,
morphology/PDE/exemplar/plate/radial/material algorithms remain distinct duties.


### RGBexclusion/AND masks and source ownership (2026-10-21)

Existing reconstructRaster accepts NotNear and sat_lt in shared RasterSelection
facts. The oldflat JSONkeys remain; RasterErase.All holds atmost32extraAND
clauses, each with its own tolerance. Near uses maxRGBdifference<=tol, NotNear
uses its strict complement; alpha is ignored. sat_lt is maxRGB-minus-minRGB.
Validate every clause before per-pixel shortcircuit and charge clausework in
existing composeCells before cloning. Root/erase/nestedclause canonical keys
are ownedobjects; dynamic icon IDs remain data. Other source OR/morphology
grammars cannot be flattened into this list.

The new two-exclusion profile reuses frozen originaltutorialsource and the same
font-free CLI. Cream had no actualpanelmatches; measuredgreen provides a
meaningful secondexclusion. Keep the original literalpanel/cream oracle intact
and disclose calibration. Proof tools/go/evidence/reconstruction-mask-proof.json
binds originalRGBAmasks/18wholeimages, old45regressions and oldacceptedcodec
projection/nativecontainment, not independentencoder orart approval.0new
functions/files; code+profilegrowth charged; fullsuite/gameplay deferred.


### Canonical narrative audit — 2026-10-21

Use the existing Go `--stream-audit-profile` with the self-contained
`tools/go/examples/canonical-audit/profile.json` contract. Registry EN comes from
the pinned registry; context comes from a separately pinned original file window.
Declare no-wrap or exact character budgets, then reuse controls/encode and the
existing observed reference/full-window mapper. Never feed expected byte buffers
as canonical authority or retry prefix variants until one matches. Canonical
comparison is absent on generation/observed-decode failure; keep original facts.
The old row status remains original-versus-observed, so compared is not canonical
success. JP-equal bytes may also match canonical wording. Generated spans use
buffer offsets; observed post-END tails remain separate. Explicit null policies
and budgets refuse via shared checkJSON field-scoped null validation; old callers
keep their defaults. Source literal oracles establish this finite contract, not
original renderer execution, native fit, whole-ledger parity or gameplay.


### Source-state prefixes — 2026-10-21

Use existing Go encode with decoded source context. Preserve payload-free leading
setup/nonscale-pen words in source order, replacing an existing speaker at its
original ordinal. Decode the actual prefix with existing controls, bound it to
4096 words and unique HDR/speaker, then wrap and strictly validate the translated
body separately. Do not relax global stream grammar to accept a prefix. Colour,
icons, scale, opaque parameters and body-state remain separate policies. The old
leading param8 path loses eight payload bytes: retain a refusal rather than copy
that bug. Original-executed finite fixtures establish encoding/read-only canonical
comparison, not native fit or patch authority; full write validators still apply.


### Explicit plain source colour — 2026-10-21

Original plain and mixed authoring are explicit caller choices: identical source
and wording may succeed plain and refuse mixed. Use canonical audit policy
`authoring: plain` only when source-leading colour should persist; omitted or
`markers` retains positional-marker requirements. Plain rejects every literal
`{{`, including malformed markup, and proves colour occurs only before content.
Copy source-prefix colour in original order/speaker ordinal, outside body budgets
and highlight-pair checks; existing decoder validates copied source state and
strict validator checks generated body. Source copy b001..b7ff is distinct from
authored marker b001..b009; do not expand marker range, change global readiness,
mutate caller context or retry failed markers as plain. Body colour/icons/opaque/
scale remain refused. Read-only generated expectation establishes no native fit
or patch authority. Preserve whole original positive bytes and meaningful refusals.


### Bounded literal inline fields — 2026-10-21

Fixed16 labels contain eight little-endian glyph words, no END; zero is space
and every word after a zero still needs validation. Reuse nonterminated literal
encoding and the shared bounded scanner; terminated markup semantics stay separate.
Preserve present empty EN versus missing/null, validate source first, refuse text
over16B, then zero-pad. One struct_table_field site with ID==structVMA, offset0,
stride16 and no pointer establishes field ownership. Observe four raw u32 values
without interpreting any as an address; Target must remain null. Independently
map the complete16B source and observed field into file-backed ELF extents.
Unbound raw windows establish no registry ownership or canonical authority.
Original helper execution and manual whole-field source equations are different
evidence; do not claim original-main replay or arbitrary insertion-order alias
parity. This read-only audit grants no native-fit or patch-write authority.


### Sentinel recognition versus loaded bytes — 2026-10-21

Read-only extracted ELF mapping must prove installed dispatch and physical loaded
allocation separately. Pin the full source and declared retail EOF. Map all twelve
base/length/loader/count instruction words through ordinary PT_LOAD only before
adding external transport; require exact LUI/ORI/register roles, two matching
window copies and positive signed16 sector counts. Byte count, both sector counts
and the full sector-aligned physical trailer must agree. Verify zero padding and
that the complete dispatch window overlaps no LOAD memory, including BSS.
Only the loaded intersection becomes sentinel_blob, with no program header.
Frozen6e recognizes1MiB but loads640KiB; dispatch-only bytes remain unmapped.
Reuse the interval projector without coalescing PH boundaries. Bind each full
selected stream window, including requested tails, to the independently observed
stored target and exact physical range. A valid target point is insufficient.
Reference target_mapping stays ordinary ELF-only; observed_mappings and explicit
allocation facts establish the external transport. Retail EOF remains a declared
layout assumption; installed code/file bytes prove no runtime execution, allocation
ownership, safe placement or patch-write authority. Never copy the legacy low16
mask-only hook checks or raw-END payload scanner as a safety contract.


### Pinned one-word raw stream reading — 2026-10-21

Reuse controls with an exact count, full-span SHA, explicit final END byte offset
and exact role word/byte-coordinate facts. Verify first END is the final word,
roles are unique/even/before END, and payloads are nil. Substitute only a local
copy with known one-word4801, run the shared decoder, prove one token per word
and every offset, then restore original roles before summaries. Never turn this
read interpretation into encoding, fitting or placement permission. Existing audit
owns side-specific pins and independent reference mapping; null nested pins/roles
yield controlled unknown sides, never successful defaults. Use existing JSON key
tracking for required Word/Offset even when zero; omission differs from zero.
Keep rawarg/rawcontrol distinct; derive any extra rawcontrol projection from
existing tokens rather than duplicating public state. Exact source hashes and
manual role normalization are finite evidence, not all-cohort equivalence.
Frozen modified title streams contain zeroSPACE and ENDf800; a NUL label in old
comments is insufficient to invent a reader. Pristine title grammar stays unknown.


### Reuse by proving raw-role compatibility — 2026-10-21

Before adding a source-pool decoder, replay selected original helpers on bounded
frozen bodies and compare their tokens against the existing exact one-word raw
contract. Store independent span hashes, exact words/byte offsets and normalized
full tokens in the existing oracle; extend its existing test loop. Matrix4800 and
status069B000/D800 need source-backed kind-label normalization only, never payload
flattening or blanket legacy equivalence. Preserve a genuine8B-payload counterexample.
The finite31native+2literal corpus required no production changes. Source scope,
caller/reference authority and runtime ABI remain separate from stream grammar.


### Event text selection through declared pool slots — 2026-10-21

Frozen event outer rows at4cecec have12Bstride and contain poolslotVMA,eventID,
scriptVMA. Source-proven ordinal slots start536920 with8Bstride, not4. Read the
slot's firstword with the existing pointer-array observer and map its full declared
stream window through the existing ELF/sentinel owners. Keep outer/event/script
provenance separate; aYBS header is not runtime-selector proof. Never treat an
outer row as the textpointer site, infer currenttext from historicalregistryID, or
let landing metadata replace observed words. F130 oldID4acd40 contains code;
source caller instead names slot536940 with observedtarget403eae0. Three actual
frozen installed reads and five meaningful binding refusals required no new Go.
Explicit outer-only metadata stays unsupported until source-proven slot supplied.


### Observing GP-relative references — 2026-10-21

Reuse canonical gp.json ID/site facts with addiu_vma/reg; no new pointer adapter.
The existing ELF owner reads one aligned uncompressed24B SHT_MIPS_REGINFO
record, GP atbyte20, retaining section index/range or explicit unknown/error.
ZeroGP is valid; duplicate/missing/short records cannot choose a base. The shared
target interpreter requires ADDIU,rs28 and exact destination register, then adds
signed imm16 modulo32bits. Ordinary mapping independently classifies targets;
full audit windows still need complete observed binding. Metadata GP is not a
runtime register observation. Keep GP patch routes refused. Native6e GP536bf0
with9IDs/10sites/8distinct bodies matches independent original facts; Male/Female
share one combined stream and NumberPlayers has a nullcheck site. Do not turn
those values into separate display ownership. Append GP report caveats AFTER
the base Limits selection; assert their actual published strings.


### Assess reader coverage by responsibility — 2026-10-21

Use the frozen source-dispatch crosswalk to separate a missing shared read
operation from missing dataset evidence. Close a capability checkpoint only after
original helpers, complete bound windows, unknown/refusal behavior and independent
challenge cover the identified forms. Fixed16, ordinary/sentinel, raw roles,
declared event slots and GP-relative references meet the bounded reader criterion.
This adds one planning credit, not a Full family or universal historical coverage.
Keep installed self-comparison, pristine context, runtime ownership and write
authority separate. Proposals and linked progress/fit reports are later duties.


### Read-only registry proposal joins — 2026-10-21

Enhance auditStreams instead of a second reconciliation pipeline. Optional
per-ID review facts belong in its existing entry table. Absence is unknown;
explicit allow is editorial scope for pinned inputs, never supplied byte proof.
Require current drafted status, known exact canonical bytes, zero observed tail
and all-site/full-window binding before suggesting machinefields. Preserve
human EN/JP/note and patch_ref. Already-patched means no status promotion, with
landing metadata attention; it does not certify allmetadata. Inline machine
policy stays explicit/held until source-proven. Scope status-key validation to
selected raw entries; nested opaque metadata retains its prior policy. Recheck
all input hashes/identity before buffered JSON. A downstream field publisher
must independently verify pins/policy; no apply authorization follows from a
candidate. Extend the existing CLI test owner; literal fixture-specific colour
cases must remain scoped to their fixture, not every new canonical profile.


### Inline machine proposal policy — 2026-10-21

Original fixed_field_writeback_main1137..1145 stores ownfieldVMA as landing,
not one of fourglyphu32words as pointer. Existing inlinegeometry/original+
observedfull16Bmaps already own this location. Reuse the existing reviewed
proposal path; preserve exactpadding/emptyEN/capacity/control/currentstatus
unknowns. Raw pointer_vma keypresence musthold evenempty/null peroriginal1058;
keep this gate inselectedrawregistryfacts ratherthan changing existingtypedread
normalization. Extend existinggeometrytable withpresencevariants andunreviewed
completeparity. AttributionPATCH_REF stays separateapprovedpolicy; do notinfer
it fromreviewreason/evidence. No newfunctions/types/runtimefiles required.


### Composed Go reports and structural diagnostics — 2026-10-21

Compose existing audit, authored-fit, CSV and status commands with matching
role-specific source hashes and explicit selected-ID coverage. Neither matching
IDs nor matching hashes alone proves a complete join. CSV/status describe the
plan. Compare encoded hashes before calling authored fit an installed-stream
measurement; source headers can make those bytes different.

Use optional audit entry line_limit1..4096 for source-defined token/page counts.
Reuse decoded tokens; never scan opaque payload bytes as controls. Ignore SPACE,
count nonzero blank glyph/HL/icon/param8 once, trim trailing zero lines, preserve
empty pages, and index overflow among nonempty pages. Headerless warnings compare
summed nonempty-page line counts against the explicitly declared original window;
unreadable reference means unknown, known empty means no positive advisory.
These are structural diagnostics, not native geometry or publication permission.

Deep-copy negative-test recipes before injecting forbidden fields. Otherwise a
shared map can contaminate saved audit evidence even when raw Go output is clean.
Freeze original expectations before implementation; test all parsed case facts
and retain the full source archive, while dropping unused duplicate fixture
metadata. Assess original family contracts only after independent behavior and
source challenges; implementation growth alone earns no coverage credit.


### GP-base indexes and instruction-flow source separation — 2026-10-21

Index supported GP-base address forms through the existing reference report and
ELF mapper. A unique forward LOAD map does not prove a unique reverse file map:
disjoint VMAs can alias bytes. Require complete aligned source-word partitions.
Use fixed metadata GP explicitly; known zero differs from unknown. Memory forms
identify effective slots, never loaded pointer values; numeric rt is bank-specific.
Keep discarded ADDIU calculations distinct from retained address definitions.
Map deduplicated computed byte points in bounded existing-mapper batches; neither
point membership nor file-backed storage proves an entire access or live reader.

Freeze literal original-helper expectations before implementation, retain their
known mistakes as historical observations, and record primary-source corrections
separately. In flow analysis, likely-link annul, JALRrd0, conditional MOVZ/MOVN
kills and unresolved indirect exits require explicit treatment. Share finite
opcode/effect facts before adding another classifier. Graph def-use traversal is
a distinct responsibility; do not append a full Tracer to references merely to
preserve function count. Branch indexing alone does not satisfy actual original
reaching-def/use callers. No CFG/hook/cave permission follows from an index.


### Finite instruction facts before graph analysis - 2026-11-04

Use instruction_index for pinned aligned source-word windows, not graph results.
Share one finite address-form table with GP indexing and retain unsupported rows.
Normal-completion GPR destinations do not imply whole128-bit kills; merge/
conditional incoming dependencies and non-GPR banks remain explicit. Resolve
next/delay membership by the exact selected VMA set, including disjoint/reordered
LOADs and32-bit wrap, never physical adjacency or numeric min/max. Keep raw
branch alternatives beside delay errors. Links do not imply return. Independent
source expectations must precede implementation; reuse existing ZIP/CLI tests
rather than append another runner. Actual before-read definitions and after-write
uses require predecessor-specific delay states and explicit unknown exits; future
pure graph analysis is a separate justified responsibility, not a fullTracer append.


### Unknown-frontier closure in bounded graph queries - 2026-11-04

Reuse decoded instruction facts and build one context graph per batch. Normal entry provenance survives backedges; pending delay states retain controller and outcome. An annulled likely path must not inherit an unused delay error. A known query root does not close unknown predecessors: reachable unsupported or unresolved indirect transfers may return to selected words. Keep known lower-bound facts and explicit incomplete reasons. Forward value searches may stop at a definite low32 overwrite without incoming preservation, shielding later unknowns. Freeze reserved-alternate and indirect-target counterexamples, plus kill shielding, independently of candidate output. Preserve earlier capsules when a manual oracle assumption proves wrong; a passing golden is evidence only for its actual contract. No whole-program/ABI/hook or patch authority follows from local graph facts.


### Fresh graph ownership joins and bounded input intake - 2026-11-04

Share the finite instruction producer between index and registry reports; keep byte decoding, graph traversal and registry policy with their existing owners. Query all selected nonzero LUIs before one bounded graph call, including unregistered or unreachable values, and refuse query overflow before analysis. Preserve exact full-pair collision keys separately from lower-reader ownership; an exact per-ID benign tuple never waives unknown frontiers or another source LUI. Retain all owner statuses and canonical-pair errors. Caller eligibility under declared entries is not patch authority or full Tracer equivalence.

Reject known special files before open can wait on a FIFO producer, then verify the opened handle against the pre-stat identity. Route recipe and reused-base bytes through the existing bounded reader; retain tighter operation-specific caps and streaming image support. Test potentially blocking regressions in deadline-owned subprocesses rather than hanging an in-process suite. This guards stable special-file inputs, not hostile atomic path swaps. Preserve directory-expansion semantics and independent source-derived expectations when fixing lifecycle boundaries.


### Reuse fixed permission facts before adding geometry - 2026-11-05

Count distinct active source facts before porting an offered geometry API. Eleven identical rounded permissions reduce to one pinned rectangle table: thirteen coalesced rectangles reproduce all80254 original allowed pixels exactly. Freeze full original masks and compare every byte, including excluded corners; bounding rectangles and visual similarity are insufficient. General parameterized geometry remains unsupported.

Bind shared permission data at the existing render resource owner, beside fonts. Reuse the bounded input reader, exact size/hash pins, closed JSON checks and existing compositor. Tables contain only allow/exclude/allow_add arrays; local erases and order stay in the profile. Refuse inline/shared conflicts, nested references and unexpected table fields. Validate raw root/render ownership before decoded optional pointers: a later null duplicate must not hide an authored request and turn a refusal into PNG export. Keep source-derived native goldens, both old inline and shared routes, and apply-output-absence shadow probes. No new helper or mask engine is required.


### Share source-pixel predicates and topology - 2026-11-05

Freeze original full masks and RGBA ordering witnesses before porting source-pixel providers. Normalize source facts into finite OR-of-AND groups and a fixed morphology pipeline; keep near and far tolerances as separate conjunctive atoms. Signed channel differences, strict fractional thresholds, empty OR versus empty AND and absent versus explicitly empty core affect permissions. Zero final growth skips, while zero core growth converges. These contracts belong in recipe normalization and concise type documentation.

Reuse selectRaster for current erase selection and original permission masks, with image choice owned by the caller. Reuse transformRasterMask for erase growth, font counters and footprint topology; outputs must never alias immutable core inputs. Four-connected crop-local topology is distinct from glyph discs, eight-connected source components and growth after whole-canvas placement. Keep global positive/subtract/add stages, native-footprint intersection and ordered composition in their existing owner. Charge bounded work once before pixel evaluation.

Use one closed validator after inline or pinned shared-table resolution; validate raw render/reconstruction ancestors before optional decoded pointers. Preserve old complete reports, styled native pixels, source refusals and apply-output absence. Compare the entire original expected masks on multiple source contexts and shifted origins. A data-only input projection must copy original expected bytes, never derive them from the candidate. Separate runtime growth from tests/evidence and award no full-family credit for a subset of permission providers.


### Reuse component traversal and separate sampling bounds - 2026-11-05

Component size, foreground seed membership and whole-component tag veto belong in one connected-component traversal. Reuse the existing minimum walk rather than adding a labeler per provider. Keep four/eight component connectivity separate from four-neighbor growth and hole filling. A present empty seed list means no selected components; preserve it as a nonnil empty slice after conversion, while an absent list keeps all components. Validate every seed against foreground, including later seeds after an earlier match. Return owned masks and leave tag/seed inputs immutable.

Use explicit sampling geometry inside the topology rectangle. Every main/core/tag predicate is false outside SampleRect; do not evaluate against made-up black pixels, especially for empty AND or alpha thresholds. A whole-canvas Rect with crop SampleRect permits original cropped component labeling followed by whole-canvas growth. Charge full topology area before work. Normalize valid Python negative indexing during recipe conversion and keep runtime coordinates explicit. Source-specific zero growth semantics belong in conversion facts.

Nested selector objects can have the same raw JSON depth as another role scalar maps. Reuse the closed validator on the selector subtree instead of broadening one depth allowlist and accepting aliases or unknown fields. Source flood label0 selection and post-selection erosion are distinct contracts; foreground-seed refusal alone does not implement them. Preserve full global source masks, including restored allow_add pixels, until every operand is supported. Equality of all expanded permission/native operand sequences can justify a later shared table across distinct asset keys, not automatic whole-art coverage.


### Preserve label-zero seed semantics and retire partial tables - 2026-11-05

A source seed may select label zero, which aggregates every original background pixel in the topology rectangle, even disconnected regions. Reuse the existing component traversal and keep default foreground-seed refusals unchanged. Select background from immutable component input, never from the filtered result, so removed foreground cannot become background. Require explicit seeds for this policy and refuse unsupported size/tag combinations. Preserve nil versus explicit empty seeds and rejection criteria through decoding and Go JSON roundtrips.

Apply source erosion after the selected seed union, inside its original crop, before final growth and clipping. Reuse the existing four-neighbor erode kernel: omitted/zero skips, negative converges. Charge erosion separately before pixel evaluation. Compare all original permission stages, including allow_add and final native intersection; isolated provider masks alone do not establish complete permission behavior. Equal expanded operands may share one purpose-grouped table across distinct asset IDs.

The standalone batch-c panel table is authored geometry authority. Its self-contained flattened prefixes are derived copies, not independent authored definitions. Maintain a finite update/substitute/repin contract and run BOTH existing CLI and Golden tests: source panel13/80254 validation and five derived-prefix checks complement each other. Old conversion Python is lineage evidence, not a runtime or required maintenance dependency. Retire obsolete partial runtime tables explicitly: remove active accounting, roadmap/workflow evidence, flat pins and sealed bindings while preserving immutable historical proofs and literal old fixture cases. No template language or recursive resource loader is needed.


### Preserve ordered source text atoms - 2026-11-05

Extend encode/controls/wrapPages rather than add another encoder. Consume one source control-occurrence tape, including implicit prefix header/speaker anchors, without globally extracting prefix state. Keep opaque word-plus-eight-byte arguments indivisible through wrapping and pair scans; expand only after exact occurrence order and bounds checks. Declare persistent prefix INIT versus paired HL explicitly, never infer roles from source offset or odd counts. STATE excludes scale-like HL words. Preserve body speaker LINE/PAGE anchors through layout and refuse duplicate prefix speakers before an optional override can affect more than one anchor.

Use bounded collision-free occurrence IDs and explicit zero/one character estimates, never native metric guesses. Re-decode complete source/output through END; compare the declared full control/payload tape. Restore synonymous glyph codes only at a complete validated no-op fixed point. Expose source policy through existing typed plan/fit/audit callers while retaining preimages/result pins, native metrics, references, strict edit guards and meaningful unknown results. Native serialization success does not authorize opaque image writes. Exact narrative E000 varargs and multi-rune authoring require separate established contracts. Retain independent original successes, bugs, refusals and newly authored placement literals separately; test changed wording, not only no-ops.


### Shared registry admission and consumable snapshots - 2026-11-05

Use existing authorRegistry intake, raw merge and exclusive publisher for finite declared import policies. Keep ordered marker kinds, case-sensitive code multisets and angle-marker transcription distinct from byte-aware controls. Standard CSV grammar validation normalizes quoted CRLF; retain source field spans and verify only newline normalization differs before restoring metadata. Normalize all batch IDs before collapsing them into keyed updates. Note wording never grants an occurrence waiver.

Inspect actual source identities before choosing label limits: the original drafting provenance is 282 UTF-8 bytes, so 256 would regress it. Bound the shared label before per-row duplication; 512 keeps the evidenced source. Budget the COMPLETE merged compact JSON before pretty-printing, including inherited root metadata. Reuse checkJSON string/depth traversal and standard indentation, with explicit conservative empty-container overcount and an actual 64 MiB result cap. Put this in the existing serialization default branch so author/merge/markup/addition writers share it; retain CSV/template/raw all-present cases and early read-only returns. No second JSON parser, per-pool writer or runtime budget framework.

Freeze literal source and boundary expectations before edits. Prove both sides of the budget, quoted punctuation, Unicode bytes, old-source metadata, exact whole outputs for every rewrite route and byte-noop preservation. Build tags must be nativefonts to exercise this project's native backend; an arbitrary native tag repeats the default build. Keep earlier mistaken-tag reports immutable and correct final claims with actual commands. Source constructor tables do not prove missing selection/occurrence duties or glossary reconciliation; retain their holds and honest code/data/test accounting.


### Plan registry and glossary changes together - 2026-11-05

Keep correction and glossary decisions in one complete preflight: current equals new is already applied before stale/status checks; held locked corrections may coexist with glossary advancement. Stale old text or different glossary rendering refuses the entire pair. Normalize registry IDs before indexing; glossary JP identity stays exact. Preserve all existing metadata for matching glossary wording. Keep historical note wording and separators in authored suffix data, not runtime date/term formatting.

Reuse the existing EN/note owner and one ordered document serialization loop. Unchanged members retain exact source bytes/dates as a deliberate Go idempotence contract, not legacy parity. Serialize/close both fixed Store ZIP members before rechecking all source/resource/profile bytes and invoking the existing verified exclusive file publisher once. Complete artifact on successful return does not mean atomic pathname visibility or installation of two files. Keep human drift/force/source construction in its own later policy.

Result limits must match consuming limits: allowing one new glossary term beyond the reader count produces an unusable next input. Test the final available slot, the first overflow refusal and consuming the emitted members again with exact whole-archive identity. Retain initial findings and independently frozen member states before fixes. Typed/null/Unicode/duplicate/source-drift and complete-plan failure checks belong before publication.


### Human source joins and independent wording ownership - 2026-11-05

Keep source relationships separate from registry state. A pure source resolver can own three-way decoded/flow/authored joins, ordered exact-spelling decoded precedence and explicit JP overrides. It cannot see statuses or publish. Existing registry ownership retains complete transition planning, the canonical status sequence, insertion, field mutation, source/profile rechecks and exclusive output. Share missing-row insertion without using the ordinary-add shortcut for existing human rows: matching, locked and drifted wording still permit metadata refresh.

Inspect actual resource availability before treating a source-only study as a missing-data blocker. The original decoded data includes an unaddressed placeholder; ignore missing/null/empty decoded VMAs while requiring every flow ID to resolve. Reject aliases within one resource before collapsing IDs, and make numeric joins across resources explicit. Validate only the last winning JP after overrides. Overrides fill a field, never a missing source row.

Keep known-unlocked force separate from locked wording and default drift preservation. Selected-only completeness and changed-only byte/date noops are deliberate redesigns: the original global assertion refuses the current registry because unrelated rows lack metadata. Preserve that refusal as historical evidence; use the existing status report for global completeness. Compare decoded string values only after Unicode checks so unpaired escapes cannot become a replacement-rune false noop. Include the new operation in the existing raw-profile text policy as well as its resource policy.

Captured62human facts,52literal correction intents and17glossary proposals are separate purpose-grouped tables. Historical annotation suffixes are already data; an explicit old-equals-new Doom row must never append an annotation. Do not add per-term, per-agent or date-formatting runtime handlers. Freeze original expected states before candidate application. Distinguish whole-document semantic parity from exact emitted-byte replay and current applicability.


### Registry pool facts and exact-text marker reviews - 2026-11-05

Keep fixed constructor, keeper and note decisions in purpose-grouped data, not per-pool handlers. Current normalized cohorts can represent reviewed fixed selection decisions without adding a generic winner-selection framework. Retain missing historical temporary-input replay as an explicit limitation; never claim it from current cohort parity. Historical constructor data must refuse evolved current wording conflicts.

Declare source admission policies explicitly. Full sweep checks ten required truthy fields and straight-apostrophe, speaker, page, glyph and marker-kind contracts; an eight-field code-multiset preset is not equivalent. Bind reviewed reorderings to exact decoded UTF-8 JP/EN hashes and a complete one-based EN-ordinal to JP-source-position bijection. Compare every mapped kind/code, validate supplied reviews even when default order agrees and refuse unused records. Notes never waive marker integrity. Code-only source metadata does not prove opaque native payload bytes.

A runtime table can be either a profile or an input resource. Keep explicit disjoint pin maps, exact directory coverage and every prior hash; validate profiles with the strict recipe decoder and resources with their consumers. Do not broaden a skip condition or repin unchanged inputs to silence golden failures. Measure implementation, recipe/example data and test overhead separately, and assess material original-family scope independently of cohort success.
