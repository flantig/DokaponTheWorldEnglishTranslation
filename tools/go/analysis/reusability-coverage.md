# Reusable Go workflow coverage

The current [v3 coverage](reusability-coverage.md) is **13/15 fully verified core families (86.67%)**, with two Partial and none Unsupported. The [granular roadmap](migration-roadmap.md) exposes all **90 acceptance groups: 85 proven (94.44%)**, six per family. Probe orchestration and evidence is Partial with **2/6** groups proven in Go. These are capability/checklist counts, not code reuse, effort, time or script migration percentages.

The original14 authoring families retain their scoped usable operations. The new full probe workflow has no verified Go orchestration owner. Existing Python remains the sole production owner until identical native acceptance and explicit handover. Starting a story probe, unattended crash/stall detection, bounded recovery, safe stop/resume, preservation and bounded evidence/resource use are required. The probe owner must agree the soak duration, recovery outcomes and budgets before acceptance; earlier three-story tests do not prove unattended acceptance.

The [v1 baseline](reusability-coverage-baseline.json) remains byte-identical. Its accepted808 views preserve **10/14 Full (71.43%)**, **76/84 (90.48%)** and expanded **10/17 (58.82%)** as history. The original three optional runtime groups are retained as non-additive facets of the one new core family, so v2 introduced 15 unique families, which v3 retains. Native hook/counter/ABI duties and fixed-field, narrative, positional-grid, code/hook/capacity and image-state scenario duties remain in scope. No Go/runtime implementation, new native proof, retirement or capability credit follows from this taxonomy update.

The [accepted raster criterion](../evidence/reconstruction-row-proof.json#current_raster_criterion_assessment) completes raster6/6. Five rows remain uncredited: four probe criteria and image_layout.06's reviewed retired disposition, which is not an instruction to implement a retired allocator. Reviewed typed-read, capture and offline lifecycle/resume capabilities are recorded in [the offline proof](../evidence/probe-records-proof.json), with no `.03`–`.05` credit. Native/current-diagnostic qualification, agreed resource/soak limits and derivative resize parity remain held; `.06` producer planning is separate. Python remains the production probe owner.

| Core workflow | Checklist progress | Status | Scoped input → output | Shared owners to enhance | Remaining gap |
|---|---|---|---|---|---|
| Guarded edits and verified output | **100% (6/6)** | Full | Pinned source + reviewed edits → dry-run report or verified new copy. | [`plan`](../patch.go), [`validateEdits`](../patch.go), [`verifySource`](../patch.go), [`patchCopy`](../patch.go), [`writeNewFile`](../outputs.go) | Source-bound typed forward/reverse and coupled code/text copies verified. |
| Text encoding, decoding and controls | **100% (6/6)** | Full | Registry wording + glyphmap → encoded bytes and control checks through fit/plan. | [`encode`](../patch.go), [`controls`](../patch.go), [`glyphMaps`](../glyphs.go) | Source-bound setup/pen/opaque authoring and mixed roundtrips verified; native/ABI/write domains retain explicit holds. |
| Consumer layout and text fitting | **100% (6/6)** | Full | Native source + wording + consumer profile → read-only line/overflow report. | [`inspect`](../patch.go), [`controls`](../patch.go), [`wrapPages`](../wrap.go), [`previewFit`](../fit.go) | Conditional source-qualified geometry/plain-child diagnostics accepted; runtime viewport/producer closure, A000 authoring and physical/vertical fit remain unsupported. |
| Instruction and reference inspection | **100% (6/6)** | Full | Pinned ELF + reference queries or guarded words → advisory report or bounded word plan. | [`references`](../references.go), [`plan`](../patch.go) | Accepted finite consumer/hook contracts retain UNKNOWN and external source boundaries; no general ABI/global-reference claim. |
| Image mapping, allocation and capacity | **83.33% (5/6)** | Partial | Pinned source + named extent/allocation facts → checked layout and edit plan. | [`inspect`](../patch.go), [`isoFileExtent`](../cmb.go), [`plan`](../patch.go) | Independent finite landing ownership accepted; preserve current stream coherence and the retired-design zero-credit disposition. |
| Registry authoring, import and merge | **100% (6/6)** | Full | Pinned registry + authored source joins, paired corrections/glossary or reviewed drafts → guarded new snapshots. | [`resolveHumanEntries`](../registry_human.go), [`authorRegistry`](../registry_authoring.go), [`checkJSON`](../inputs.go), [`writeNewFile`](../outputs.go) | Original material contract verified; raw legacy temporary replay and native payload equivalence not claimed. |
| Registry versus installed-content reconciliation | **100% (6/6)** | Full | ELF/queries → advisory matches; independent original/installed inputs + registry EN → source-aware canonical comparison facts. | [`references`](../references.go), [`controls`](../patch.go), [`authorRegistry`](../registry_authoring.go), [`auditStreams`](../stream_audit.go), [`checkJSON`](../inputs.go) | Reviewed pointer/inline proposals, meaningful unknowns and field-owned publication preview verified. |
| Versioned snapshot and restore management | **100% (6/6)** | Full | Regular file + tag/revision → snapshot/receipt; explicit tag → verified new restore output. | [`snapshotArtifacts`](../snapshots.go), [`readInput`](../inputs.go), [`writeNewFile`](../outputs.go) | Frozen explicit-version contract verified; legacy-format import and workspace-wide reporting remain separate. |
| Offline evidence reports and exports | **100% (6/6)** | Full | Pinned source + table/profile → JSON; pinned registry → CSV; registry/glossary/flow + template → Markdown. | [`references`](../references.go), [`controls`](../patch.go), [`authorRegistry`](../registry_authoring.go), [`auditStreams`](../stream_audit.go), [`checkJSON`](../inputs.go) | Operational Go structure plus identity/coverage-qualified audit, authored fit, CSV and progress composition verified. |
| Candidate composition and containment | **100% (6/6)** | Full | Compatible recipe tables + source → composed validated plan or verified new copy. | [`plan`](../patch.go), [`patchCopy`](../patch.go), [`run`](../main.go) | Covered for reviewed, source-bound proposals. |
| Texture and font-atlas codec | **100% (6/6)** | Full | Pinned texture/atlas + profile + optional PNG → PNG export or new native texture. | [`indexTextures`](../texture_index.go), [`texture`](../texture.go), [`authorTexture`](../texture_authoring.go), [`generatePalette`](../texture_palette.go) | Original codec contract verified; unsupported formats retain refusals. Rendering, previews and placement are separate. |
| Named ISO/CMB asset placement | **100% (6/6)** | Full | Pinned ISO + bundle + named member/file table → verified new image. | [`isoFileExtent`](../cmb.go), [`cmbIndex`](../cmb.go), [`planBundle`](../cmb.go), [`patchCopy`](../patch.go) | Covered for named, fixed-size, guarded replacements. |
| Text and donor-based raster rendering | **100% (6/6)** | Full | Pinned texture + font + cell/run/group profile → bounded rendered texture through the shared importer. | [`composeCells`](../raster.go), [`authorTexture`](../texture_authoring.go), [`texture`](../texture.go), [`writeNewFile`](../outputs.go), [`renderRuns`](../raster_runs.go), [`pixelOver`](../raster_runs.go), [`resizeRaster`](../raster_resize.go) | Current fixed-data/material decisions and editable donor/order containment accepted; arbitrary generators, pristine provenance and gameplay are not claimed. |
| Asset specifications, previews and inventory | **100% (6/6)** | Full | Pinned TXD/CMB/PNG + profile → inventory, discovery/contact ZIP or RGB comparison pair. | [`authorTexture`](../texture_authoring.go), [`manifestTextures`](../texture_manifest.go), [`contactSheets`](../texture_contacts.go), [`textMasks`](../raster_font.go), [`decodePNG`](../raster_png.go), [`resizeRaster`](../raster_resize.go), [`pixelOver`](../raster_runs.go), [`writeNewFile`](../outputs.go) | Original contract verified; normalized geometry/serialization policies and finite native-font limits remain explicit. |
| Probe orchestration and evidence | **33.33% (2/6)** | Partial | Pinned saved records/evidence → offline linkage and cohort reports. | `admitProbeRecords`, `reportProbeEvidence`, `readInput`, `checkJSON`, `run` | .03-.06 typed reads, capture, lifecycle and handover remain; no live authenticity from saved claims. |

Thirteen families are complete under their reviewed contracts. Image layout remains5/6 with a retired zero-credit disposition; probe remains0/6. Source, runtime and gameplay limits remain explicit in each canonical assessment.

### Earlier implementation checkpoints

The [paired stream audit](../evidence/stream-audit-proof.json) extends Partial
reconciliation and offline reports through [auditStreams](../stream_audit.go),
existing `controls` and shared [checkJSON](../inputs.go). Explicit pinned windows
produce separate raw/content/control/argument/payload facts; failed semantics
remain unknown. Four public example files count as runtime. That prior increment was
+13,711B production and +5,848B runnable examples, with +13,116B tests and +64,761B
fixture separately. That checkpoint had native runtime107files/785,040B; production30files/
302,492B and31named functions. This is capability growth, with no family,
historical-retirement or reduction credit. Native3case checks use frozen ELF
bytes; the JP-source case does not verify its sentinel translated target.

The [observed declared-reference report](../evidence/observed-reference-proof.json)
now shares [geometry and strict word interpretation](../reference_geometry.go)
with existing patch planning. It retains site ordinals, raw words, divergent
targets and complete-word ELF mappings; unavailable facts stay unknown. Native
checks cover four IDs, nine sites and 18 words, including an unmapped target.
That checkpoint had runtime **109 files / 796,740B**, production **31 files / 313,749B**
and **33 named functions**. This increment grows runtime by 11,700B, tests by
15,942B and fixture/catalog data by 16,048B separately. It earns no family,
historical-retirement or reduction credit. Live reader selection, full stream
reconciliation and gameplay remain unproved.

The [reference-bound audit](../evidence/reference-bound-audit-proof.json) now
connects existing reference observations and paired comparisons. Every selected
site must be valid and converge; the complete explicit observed window must map
from that target to the declared file span, including tails. This adds **no
function**. Current runtime is **114 files / 808,049B**, with **31 production
files / 317,296B and 33 named functions**. Growth is 3,547B production plus all
five example inputs at 7,762B; tests grow 6,370B and fixture data 90,845B separately.
Plain audit output remains byte-identical. Native three-label self-comparisons
prove source facts, without family, historical-retirement or reduction credit.

## Denominator and calculation

The [v3 baseline](reusability-coverage-baseline-v3.json) retains the 15-family denominator and all 90 IDs. The [authoritative scope amendment](current-tooling-scope-v3.json) changes exactly two current obligations; all other 88 rows and every existing Go credit are unchanged. The [accepted-834 v2 assessment](reusability-coverage-v2-accepted834.json), [roadmap](migration-roadmap-v2-accepted834.json), [Markdown view](reusability-coverage-v2-accepted834.md) and [checks](../evidence/reusability-coverage-checks-v2-accepted834.json) preserve the prior requirements and statuses exactly. Reviewed historical disposition earns zero Go credit. The original runtime groups remain non-additive facets of the probe family.

```text
core coverage = 100 × 10 / 15 = 66.67%
checklist index = 100 × 76 / 90 = 84.44%
```

The [byte-exact accepted808 v1 assessment](reusability-coverage-v1-accepted808.json), [roadmap](migration-roadmap-v1-accepted808.json) and [Markdown view](reusability-coverage-v1-accepted808.md) retain core10/14, checklist76/84 and expanded10/17 history. Their historical/current-at-the-time language is not the current v3 score. The original [v1 baseline](reusability-coverage-baseline.json) is unchanged. Its three crawl hashes still match; original context-plan f099 remains unrecovered and current2d6 differs, so there is no blanket original-source provenance claim.

Probe is Partial because inherited static guarded-word/template diagnostic facts exist. Its operational platform and scenario facets remain unproven in Go. All six new acceptance groups earn0, and preserved Python operational support is not described as broken. Checklist arithmetic does not automatically promote a family; all material duties require independent evidence. Scope expansion is not a regression in the preserved original capabilities.

### Full probe acceptance groups, all unproven in Go

| Stable milestone | Acceptance and current gap |
| --- | --- |
| probe_orchestration_evidence.01 | Run records and ownership receipts: Versioned metadata, profile receipts and session records validate required identity and nonce linkage, schema/version, path roles and exact error/refusal order; missing, stale, conflicting and duplicate evidence is refused. Credit0. No verified Go admission contract or owner-approved synthetic receipt oracle. |
| probe_orchestration_evidence.02 | Checkpoints and acceptance reports: Deterministic event/cohort reports preserve native slots, exact fingerprints, ordered evidence, warm/cold distinctions and unknown outcomes across fixed-field, narrative, positional-grid, code/hook/capacity and image-state comparisons. SKIPPED and UNKNOWN outcomes retain their reasons and source ordering and never count as passing coverage. Credit0. Existing offline reports do not establish probe event semantics or original scenario cohort parity. |
| probe_orchestration_evidence.03 | Typed reads and diagnostics: Build/session-bound typed memory reads and decoders match owner oracles and refuse stale/partial/malformed/unsupported reads. Versioned diagnostic hook/counter plans, saved/live provenance and material displaced-instruction/ABI obligations are independently verified. Credit0. Static Go hook/template facts are partial support only; no complete owned diagnostic/read pipeline or ABI proof. |
| probe_orchestration_evidence.04 | Capture and evidence linkage: Serialized captures tie frame tags, decoded UI, image paths, logs and checkpoint outcome to one process/session; timeout, partial and cross-session/race cases are preserved/refused; owner-operated native comparison confirms parity. Bounded evidence retention and resource budgets are agreed with the probe owner and verified, including stalled/partial capture behavior. Credit0. No verified Go capture pipeline or owner-exported exact capture contract. |
| probe_orchestration_evidence.05 | Owned runtime lifecycle: Exact PID/starttime/build/ISO, profile receipt, PINE, virtual-pad, IPC/session/nonce and private card roots govern lifecycle and cleanup. Warm reset differs from cold restart; preservation/post-flush hashes and adversarial ownership refusals pass under one controller owner. BIOS/card/controller identities are guarded. Unattended crash/stall detection, bounded recovery, safe stop/resume and post-flush preservation pass under owner-agreed limits. Bounded skip/attempt policy preserves SKIPPED/UNKNOWN outcomes without granting coverage or unbounded polling/retries. Credit0. No verified Go lifecycle replacement; existing Python remains operational owner. |
| probe_orchestration_evidence.06 | Native scenario parity and handover: Exact-source smoke and three sequential stories, nondefault slot creation/paired reload, preservation/overwrite/retry, verified advancement and broader required cohorts pass; independent acceptance authorizes one-owner handover without duplicate production FSM. Starting the story probe and leaving it unattended requires owner-agreed bounded soak duration, recovery outcomes, resource and evidence-retention acceptance. These limits remain TBD; prior three-story tests do not establish this acceptance. Credit0. Current-actor takeover fresh smoke/stories remain pending in authorized handoff; no verified Go scenario parity or handover. |

## Evidence and limits

The [machine-readable assessment](reusability-coverage.json) binds every family to original contracts, current owners, source/evidence hashes and concrete missing work. The [initial independent assessment](reusability-coverage-independent.md) records the original classifications and contracts; linked increments below govern subsequent changes.

The initial measurement added no production code or game application. Subsequent verified capability increments are recorded separately, including isolated word and canonical-JP restoration ISOs. Coverage changes require fresh evidence and assessment. Current Go checks pass; the broader legacy Python suite is still failed (4,041 passes / 68 classified fixture/snapshot failures). No unreached scenario earns credit.

The discovery corpus is a pinned historical input. This measurement does not claim all 410 legacy source files still match their discovery hashes, all historical CLIs are migrated, or all visual/gameplay behavior is verified.

## Current registry CSV projection

The [CSV projection proof](../evidence/registry-export-proof.json) and
[independent review](../evidence/registry-export-review.json) verify complete
canonical5,544-row bytes, five independent edge oracles and typed refusals.
Ordered scalar columns share `authorRegistry` and its existing publisher, with
no new function. Full status/glossary/flow and disc-truth reports remain outside
this increment; offline reporting stays Partial and coverage remains5/14. The
[historical CSV disposition](../evidence/registry-export-disposition-proof.json)
adds Partial responsibility credit only:8full/20reviewed/16partial/366outstanding
of410, with legacy execution unchanged.

## Current ELF mapping increment

The [ELF mapping proof](../evidence/elf-layout-proof.json) and
[independent review](../evidence/elf-layout-review.json) verify pinned read-only
PT_LOAD inventory and named ranges through `inspect` and the shared report
lifecycle. Independent precode vectors, malformed inputs, complete CLI race,
12 independent probes and frozen-executable boundaries pass. File-backed, BSS
and unmapped spans remain distinct; mapping does not prove safe caves or native
startup ownership. Image layout stays Partial and the score remains5/14.

## Current registry addition increment

The [draft-addition proof](../evidence/registry-add-proof.json) and
[independent review](../evidence/registry-add-review.json) verify new reviewed
rows through the existing registry owner. Eleven precode vectors and two
post-review counterexamples cover insertion, aliases, conflicts and exact-byte
idempotency. Final complete CLI race33.996s, independent CLI4.188s/nine probes,
build/vet/format/scans and a six-step source-shaped add/merge/replay flow pass.
Production grows2,395 bytes with no new functions, production types or recipe
fields; tests grow10,035 bytes and one4,963-byte fixture separately. Coverage stays
**5/14 Full**. This generic lifecycle does not claim the differing historical
text-validation/import policies or historical retirement.

## Current inventory increment

The [inventory proof](../evidence/texture-inventory-proof.json) and
[independent review](../evidence/texture-inventory-review.json) verify native names
and raw headers through one shared parser. The final header reuse delta passes
focused race tests and historical goldens; initial parser extraction also passed
a two-owner race run and103 old/new CLI comparisons. A real27-texture dictionary,
empty inventory and global malformed inputs preserve their source/profile files.
Production grows4,091 bytes and one shared function; tests grow5,829 bytes separately.
This is capability growth, with **5/14 Full unchanged**, not retirement or savings.

Nested Job Center substitution remains refused. The bounded
[index follow-up](nested-job-index-followup.json) and
[gender follow-up](nested-job-gender-followup.json) narrow normal input producers
but leave reachable selection bounds and accepted save-buffer provenance unproved.

## Current snapshot family assessment

The [independent requirement crosswalk](../evidence/snapshot-family-assessment.json)
and [positive multi-version evidence](../evidence/snapshot-family-proof.json)
complete the original snapshot contract: create/index/hash immutable-by-tool
versions, inventory explicit tags and verify restore before and after copying.
Per-tag receipts supply the index and retain metadata for missing payloads.
Legacy aggregate-ledger import is compatibility; broader workspace reference and
allocation reports remain reporting work. No new runtime function, denominator
change or historical retirement earns this promotion.

## Prior increments and their scores at the time

The [exact-palette increment](../evidence/exact-palette-proof.json) verifies five actual image imports and preserves all 227 prior rasters through the shared codec. Texture remains partial; no counts or denominator changed.

The [finite multipage PSMT4 extension](../evidence/multipage-psmt4-proof.json) reuses the same depth4 address expression and adds88production bytes. Existing227rasters and exact-palette fixtures remain exact; texture still has concrete remaining native modes.

The [explicit RGBA increment](../evidence/direct-rgba-proof.json) adds colored512-square version0 direct rasters through the existing pixel walk, preserving font defaults and all227priorrasters. Rawalpha0–128/hiddenRGB/masks/publication are independently checked; fiveotherdirectlayouts stay held. Core3/14 and expanded3/17 are unchanged.

The [five-layout direct extension](../evidence/direct-layouts-proof.json) verifies all21observed direct sources through actual export/no-op import, with frozen five-mode edits, alpha/mask/containment and refusal tests. Six observed native modes share the same codec; arbitrary layouts and the wider texture family remain incomplete.

The [small PSMT8 extension](../evidence/small-psmt8-proof.json) verifies four original rasters in three geometries through the same index/CLUT/quantizer/packet path, including independent exact-palette outputs and 26-sibling containment. Other small modes and approximate generation remain gaps; core and expanded scores are unchanged.

The [grouped PSMT8 increment](../evidence/grouped-psmt8-proof.json) replaces three repeated format cases with a finite19-pair set and shared allocation/base rules. Sixteen new representatives pass independent preserve/exact and CLI checks; this does not mean1,089 discovery rows were individually authored. [Astra026](../evidence/astra-audit-026.json) found no actionable issue. The [PSMT4 caller census](remaining-psmt4-frontier.json) supersedes the speculative remaining-geometry gap: all75 observed records use the two supported modes. At that checkpoint, approximate palette generation remained a real caller gap; no family score changed.

The [approximate-palette increment](../evidence/approximate-palette-proof.json)
closes the actual1,513-color caller gap with one numerical owner shared with
exact generation. Seven preimplementation whole-artifact oracles, independent
227-case regression, actual CLI safety checks and numerical mutants pass.
The family remains partial: historical128x64/128x256 full-page exports require
a further native palette-position binding. Counts and the original baseline
remain unchanged. Runtime grows5,593 bytes; test and fixture overhead is separate.

The [same-contract reassessment](texture-codec-coverage-reassessment.md) binds
the two remaining full-page modes to actual historical exports and independent
native/GS oracles. It also checks below16 refusals against the original readers.
It recommends keeping the family partial until the positive export gap is fixed.

The [full-page increment](../evidence/fullpage-tbw2-proof.json) closes the two
positive export gaps using the existing packet-position owner. Both original
sources pass native/GS and independent preserve/exact/CLI verification, retaining
all prior corpus cases and full-page flags. This adds51 production bytes and no
function or policy. A final independent family assessment is still required;
status and counts stay unchanged until that assessment is complete.

The [final codec assessment](texture-codec-final-assessment.md) now closes all
seven original codec duties and recommends Full. Root verified the current
source pins and accepted that recommendation. It includes an additional actual
256x64 export/no-op/native-join check and affirmative below16 legacy refusals.
The original baseline is unchanged: core4/14=28.57%, expanded4/17=23.53%.
Earlier partial assessments remain historical evidence. This grants no renderer,
preview, art, ISO or script-retirement credit.

The [bitmap-cell proof](../evidence/bitmap-render-proof.json) and
[independent review](../evidence/bitmap-render-review.md) move raster rendering
from Unsupported to Partial. One shared compositor creates all five approved
HUD labels from pinned font data and declarative cells, preserving native bytes
outside their masks. The original family contract still includes native/TTF
fonts, styled runs/layers and donor reconstruction. Core4/14 and expanded4/17
full coverage are unchanged; partial work earns no fractional credit.

The [fixed resampling primitive](../evidence/raster-resize-proof.json) is verified
against134 image cases and8,803 coefficients, with independent race/regression
and numerical mutation checks. It is a foundation for the selected native-font
workflow, now integrated in the bounded proof below. Raster status stays Partial;
no denominator or completion-credit change follows from this internal function.


The [native run proof](../evidence/native-text-proof.json) and
[independent review](../evidence/native-text-review.md) now verify the actual
original mini_g01 mixed-color rule through a shared95-glyph atlas/metrics and
quarter-step fitting pipeline. All output layers/native bytes match independent
references; containment, refusal/publication and six mutation checks pass.
This is one finite style, not all113 discovered operations or full-card authoring.
Raster stays Partial; counts and baseline are unchanged. Runtime code+data grows
36,712B, with test/fixture costs reported separately; no retirement or savings.

The [four-style proof](../evidence/native-styles-proof.json) and
[independent review](../evidence/native-styles-review.md) verify all four observed
native style groups through existing renderRuns/composeCells/texture owners.
Tracking, minimum fitting, semantic ordered strokes, float composition and
source-palette projection match independent references. Separate paint and ink
bounds restore the original tutorial result:6,411 changes, whole8931937b.
Root race123.166s and independent157.690s/current227, fourteen killed mutants,
build/vet/format/whitespace/credential checks pass. Zero new functions/dependencies;
11,091B runtime growth,18,095B tests and2,909,007B fixtures separately. Native total
is90files/713,413B. This is capability growth; no retirement or savings.
Core4/14=28.57% remains unchanged; raster Partial, multiline/icons/TTF/donors remain.

The [shared multiline prototype](../evidence/native-line-groups-proof.json) adds
optional `group` data to native cells: cell-relative `box`, `lines` of colored
runs, `leading` and `vertical_align` (`middle`/`top`). Shared layout supplies
style/size/minimum and `align` (`center`/`left`); omit its scalar `at`/`max_width`
for groups. Each group fits one size and rounds the destination after each line.
Fit geometry, approved writes and background paint remain distinct. Groups allow
1..16 lines within the existing raster and aggregate stroke-work bounds.
The [tutorial example](../profiles/textures/help01-command-order.json) matches its
independent original whole TXD, decoded RGBA and11,735 native changes. Eight
frozen layout examples and focused tests/CLI/build/vet checks pass; the full
integrated/race suite is deferred. No functions added; runtime grows6,903B,
tests4,315B/fixtures280,722B separately. Icons, TTF and donors remain future
enhancements. Raster stays Partial; a usable toolkit does not require full
historical coverage.

The [focused snapshot baseline](../evidence/snapshots-proof.json) establishes
a usable tagged create/list/verified-restore path through one justified lifecycle
owner and the enhanced existing publisher. Snapshot management moves from
Unsupported to Partial; full core coverage remains4/14=28.57%, now10partial and
0unsupported. All14 areas having entry points is availability, not100% reuse.
Legacy ledger imports/workspace auditing remain separate, and the full
integrated/race suite is deferred under the latest user direction.

The [integrated registry boundary checkpoint](../evidence/registry-owner-proof.json)
passes the full uncached Go race suite145.271s and required checks. The owner map
above exposes the existing shared implementation seams. Registry policy moved
mechanically out of routing; no new feature or family credit. Runtime overhead
568B, tests/fixtures unchanged. All14 scoped entrypoints remain distinct from
4/14 fully verified family contracts and from historical script replacement.

The [three-input progress report](../evidence/registry-status-proof.json) now verifies all registry/glossary/flow facts through existing owners and one pinned Markdown template. Literal/empty/null labels remain visible; diagnostics keep source order. Layout/date/escaping are redesigned. Disc-truth exports and combined audits remain incomplete;5/14 Full and the historical410-path counts are unchanged. Runtime grows12,705 bytes including recipes/template; tests/fixture grow9,473/17,439 bytes separately. No reduction or retirement claim.

The [declared-reference guard extension](../evidence/reference-check-proof.json) enhances existing pointer_check for explicit struct fields and strictLUI/ADDIU pairs. Exact expectedwords/sites reuse plan/verifier/inspection and the read-only gate; no new function/type/schema or validator mode. Full-source/physical-scope checks, independent signedcarry/wrap fixtures, actual18nativewords and olddata output parity pass. Content/argument reconciliation, liveness and exhaustive references remain gaps. All family/historical scores stay unchanged. Runtime grows2,543B including the recipe; tests/fixture grow8,088/9,147B separately. No reduction or retirement claim.

The [exact LINE constraint](../evidence/fit-line-count-proof.json) strengthens
Partial consumer layout through the existing previewFit/controls owners. A missing
trailing menu separator can now fail despite passing maximum height. Two frozen
native plain menus match source-derived counts and widths; their scaled sibling
stays unsupported. This adds1343 implementation bytes, no new function or runtime
recipe; runtime now114files/809392B. Tests+3920B and11196B fixture are separate.
No family or historical-retirement credit;5/14 remains unchanged.

The roadmap for each incomplete area follows the same frozen requirements:

| Area | Remaining sequence |
|---|---|
| Text codec | Setup/pen/opaque authoring → source-context-preserving roundtrips. |
| Text fitting and layout | Complete source-bound scale and position maintenance with independently proven ownership and guarded replay; retain partial native ink, nested expansions and proved consumer boxes. |
| Instruction and reference inspection | GP-relative indexes → branch/register analysis → interior-reference and ABI boundaries. |
| Image allocation and capacity | Independent safe landing ownership remains held. Preserve active stream-loader metadata coherence and the reviewed historical disposition of the retired static design. |
| Registry authoring and import | Declared batch/CSV imports → text-integrity policies → glossary and field ownership. |
| Registry versus installed content | Canonical expected streams → remaining source/reader forms → reviewed difference proposals. |
| Reports and exports | Installed-content versus canonical-plan audit → joined derived exports and progress. |
| Raster and text rendering | Inline icons → pinned TTF fonts → donor/reconstruction layers. |
| Specifications, previews and inventory | Authored spec joins → complete batch manifests → checkerboard comparisons → labelled contact sheets. |

[Independent checklist assessment](sixth-family-closure-review.json) and
[current source recheck](../evidence/migration-roadmap-source-checks.json) support
this planning view. The historical410-path crawl has406unchanged hashes and4
explicit current-source dispositions; all410current files parse. No new Go
behavior, family promotion or fresh full-suite/gameplay validation is claimed.

The [authored asset join](../evidence/asset-specification-proof.json) verifies
exact pinned native selectors, annotations and decoded geometry through existing
owners. The roadmap now records **60/84 milestones (71.43% planning index)**;
family completion remains **5/14**. This increment adds 9264B runtime
(5251B production plus all 4013B example inputs), with
11056B tests and 14020B fixture separately. No new function or
net code reduction is claimed. Batch discovery scoring remains required.

The [streaming manifest](../evidence/asset-manifest-proof.json) now accounts for
every selected archive entry and its raster/error rows, joining authored facts
with measured geometry, source/pixel hashes and linked previews. Required
discovery scores, tiers and ordered flag reasons are verified against original
source oracles. Raw PNG encoded bytes are retained; their RGBA hash convention
is explicitly Pillow 12.3. Two independent-review findings were corrected and
rechecked. The roadmap records **61/84 milestones (72.62% planning index)**;
family completion remains **5/14**. Runtime is **120 files / 853,100B**, with
**33 production files / 343,343B and 35 named functions**. Growth is 19,453B
production plus all 14,991B example inputs; tests grow 21,760B and fixture data
71,017B separately. Two new shared owners have prior reuse justifications.
This is capability growth, with no net reduction or retirement claim.

The [texture-index reuse fix](../evidence/texture-index-reuse-proof.json) removes
repeated whole-dictionary parsing through existing owners, without a new function.
The 1,024-native probes drop from 1,025 index passes to one, with complete outputs
unchanged. The source-bound context requires immutable private buffers; it does
not detect in-place mutation. Runtime now totals **120 files / 853,637B** and
production **33 files / 343,880B / 35 named functions**. The fix adds 537B runtime
and 2,038B tests, with no fixture growth. This is less repeated work, not a net
source-code reduction. Focused race and independent review pass; coverage stays
**61/84 milestones and 5/14 complete families**.

The [nearest preview foundation](../evidence/preview-resample-proof.json) enhances
the existing resampler, retaining all134LANCZOS cases and numerical code. Ten
original-only nearest RGBA cases, Gray/padded views and the131072-pair digest pass,
including transparent crop padding and normal3x preview sizes. Independent extra
original-Pillow vectors and root focused race pass. This adds1895B runtime,
4967B tests and7656B fixture separately, with zero new functions. Runtime now
totals120files/855532B and production33files/345775B/35named functions. The
comparison operation is still open: **61/84 milestones and5/14Full remain**.

The [checkerboard comparison](../evidence/asset-comparison-proof.json) closes only
preview milestone.05 after17complete originalRGB/RGBA cases,2normal capacity
cases, strictprofile/source/publication checks and fresh independent review.
One justified shared PNG decoder is extracted from manifest; the existing
resampler/compositor/writer remain canonical. Current runtime124files/862508B
and production34files/352117B/36named functions include all3example inputs.
Growth is6342Bproduction+634Bexamples=6976Bruntime; tests13739B andfixture19578B
are separate. This is capability growth, not source-code deletion. Only the
planning index advances to62/84; broad-family completion stays5/14.


### Verified labelled contact inventory increment (2026-10-21)

[Contact proof](../evidence/asset-contact-integration-proof.json) and the
[fresh independent closure](../evidence/asset-contact-integration-final-review.json)
verify59 rows/16 whole RGB pages, sorting/pagination, per-group deduplication, final
CSV links, multiline captions and per-item painting order. Frozen earlier Astra
and ordinary reports retain their historical OPEN findings; the fresh report
closes both on the new pinned source. Font shaping is one optional native backend;
layout facts are in a separate table. Default builds retain other tools and refuse
labelled contacts explicitly. The public synthetic example produces13 rows / 2 pages.

Current production37 files / 386,187 B / 39 named declarations; runtime134 files / 1,696,016 B
and 222 accounted inputs. Runtime grew833,508 B, including34,070 B Go,759,720 B font,6,034 B
header,661 B layout,15,559 B notices and17,464 B examples. Tests19,427 B and fixture954,792 B
are separate overhead. Two justified logical owners use three source declarations
because the font interface has a complementary build-tag refusal. This is new
capability, not code reduction, script retirement or .06 promotion. Family coverage stays 5/14,
planning stays 62/84 and historical 410-path counts remain unchanged.


### Shared pair layout increment (2026-10-21)

[Pair proof](../evidence/asset-pair-variants-proof.json) and
[independent review](../evidence/asset-pair-variants-review.json) verify 17 original
checker outputs plus 12 flat RGBA and 10 captioned weekday RGB outputs; the two
prior checker capacity cases remain covered. Existing comparison, pixel, font and
publication owners are reused. Separate layout facts replace embedded geometry
choices. One justified PNG interface method retains opaque RGBA headers.

Current production: 37 files / 391,659 B / 40 named declarations. Runtime:
141 files / 1,718,980 B; 229 accounted inputs. Growth is 5,472 B Go and 22,964 B
runtime including a 12,676 B pinned font and 4,816 B table/notice/example data.
Tests grew 3,915 B and fixtures 80,814 B separately. This is capability growth,
not reduction, retirement or milestone promotion. Coverage stays 5/14 families
and 62/84 planning milestones. The source assessment and root replay establish
a real remaining contact eligibility defect: four original pages become zero
when numeric scoring is unavailable. Fix that shared policy before Full credit.


### Verified score-presence correction and family closure (2026-10-21)

Existing contactSheets now preserves the original successful detector-error
path: four whole pages, measured scores still null and display-only -1/0. Missing
detector records remain separate, with original duplicate-link propagation. The
[proof](../evidence/asset-contact-score-policy-proof.json) binds fresh ordinary
review, original source closure, normal/race checks and230 preserved fixture
contents. Runtime grows633B; tests1,852B and fixture40,310B separately. Zero
functions added. Current production37files/392,292B/40declarations, runtime141files/
1,719,613B and229 inputs. This closes .06 and the sixth original family, not all
410 scripts, code reduction or gameplay. Historical dated counts above remain
evidence for their checkpoints; current totals are6/14 and63/84.


### Verified shared inline icons (2026-10-21)

[Proof](../evidence/inline-icons-proof.json) binds source/frozen pixels, independent
review and focused/race checks. Existing fittedrun and linecompositor owners
now reserve fixed-size icons and copy immutable originalRGBA after each line,
including hiddenRGB with full rectangle containment.11wholeoriginalcases pass;
a normalized sourcecolour mismatch was corrected without changing expected
pixels. Runtime grows3,526B with zero functions. Raster .04 advances to4/6;
planning64/84, core6/14 and historical410-path counts unchanged. StyledTTF and
donor obligations remain open; no savings, retirement or gameplay claim.


### Verified shared TrueType source (2026-10-21)

[Proof](../evidence/truetype-raster-proof.json) and
[independent review](../evidence/truetype-raster-review.json) bind original full
images, fractional masks, implicit newline semantics, typed empty-stroke JSON,
shared cell containment, complete native projection and publication guards.
Raster milestone .05 earns5/6; total65/84 planning. Core6/14 Full and historical
410-path counts stay unchanged. Production+7,806B/runtime+637,701B includes the
font, notice, manifest and example recipe. This is capability growth, not savings.
Tests+18,532B/fixture1,599,445B are separate.

The [donor frontier](donor-reconstruction-frontier.json) recommends masked row
interpolation from current RGBA as a next finite primitive. Its source taxonomy
retains distinct PDE, exemplar, plate, radial/contour and material algorithms;
one interpolation mode cannot close .06.


### Finite row/column reconstruction (2026-10-21)

[Proof](../evidence/reconstruction-row-proof.json) and [review](../evidence/reconstruction-row-review.json)
verify ordered current-pixel flat/clear/row/column operations, exact permissions,
immutable icon sources and the shared native publication path. Production+13,759B,
runtime+15,124B; tests+21,101B and fixture350,493B separate. One new function
was justified; no savings, retirement or new completion credit. Raster stays5/6,
planning65/84,core6/14 Full. Other reconstruction algorithms remain explicit gaps.


### Finite RGB exclusion andAND masks (2026-10-21)

[Proof](../evidence/reconstruction-mask-proof.json) and [review](../evidence/reconstruction-mask-review.json)
verify18neworiginalwholeoutputs, old45regressions, currentpixels, independent
per-clause tolerances, sat_lt andexactnative/source preservation.0newfunctions
orproductionfiles; +1,924BGo/+4,114Bruntime including2,190Bprofile.
Tests+4,325B/fixture155,124B separate. No retirement/savings/completioncredit;
raster5/6,planning65/84,core6/14Full unchanged. Next cross-family investigation
is canonicalexpected-plan versus independently observed stream audit.


Canonical narrative increment: existing auditStreams derives pinned registry EN
against original context using explicit no-wrap/character budgets, then compares
the generated side with strictly bound installed text.11literal rows and guarded
unknowns verified;0newfunctions,0retirements,0milestone/familycredit. Runtime
+19201B includes4340Go+14861example data; tests6148B/oracle63279B separate.
See [proof](../evidence/canonical-audit-proof.json) and
[review](../evidence/canonical-audit-review.json).


Source-state prefix increment: existing encode preserves supported payload-free
setup/nonscale-pen source prefixes outside translated body wrapping, with original
ordering and speaker ordinal. Existing decoder validates prefix; strict body and
full write/layout guards remain.28 original-executed cases,14 positive14 refused;
7 guards and immutable caller contexts.0 new production functions/types/files.
Runtime+2022B; tests+2876B/new fixture13895B/changed fixture+1594B separate.
No savings, family/retirement/milestone credit;6/14 and65/84 unchanged.
See [proof](../evidence/source-prologue-proof.json) and
[review](../evidence/source-prologue-review.json).


Explicit source-colour increment: existing encode/audit policy distinguishes
plain persistent source-prefix colour from ordered positional markers (default).
No fallback after failed markup, caller mutation or global diagnostic changes.
50paired original route cases11positive39refused plus6actual-source synthetic
wordings,25old original mixed cases,7API/4wire/1policy guards and6CLIvariants
verified; core/native12new captures and all3completeoldreports match.
0new production functions/types/files; runtime+1698B, tests+5057B/newfixture16448B.
No savings/retirement/full-family credit; milestone criterion assessment separate.
See [proof](../evidence/source-colour-proof.json) and
[review](../evidence/source-colour-review.json).


Canonical-comparison milestone assessment: registry_reconciliation.04 and
offline_reports.05 are proven under explicit bounded narrative source policies.
The existing factors/errors express canonical match, original-only, neither and
unknown; no new status function is required. Exact original criteria place reader
expansion and joined/proposed updates in later milestones.67/84 is a planning
checklist;6/14 full families and all historical migration counts remain unchanged.
No runtime/code growth or savings in this assessment. See
[assessment](canonical-comparison-milestone-assessment.json),
[source gap study](source-aware-roadmap-gap-study.json), and
[adversarial challenge](../evidence/astra-audit-036.json).


Bounded inline16 reader: existing encoder/scanner/reference observer/audit now
handle literal glyph fields without END, with all eight words validated.
Intentional empty EN is distinct from missing/null; generated text is padded to
exactly16B only after independent source validation. Inline metadata owns a field,
not a pointer target: four raw words are observed, Target remains null, and both
original and observed full fields must map into file-backed ELF extents.
28 independent original-helper/source-equation rows,19 geometry/window/policy
guards,18 scanner guards and4096word limit verified; no original-main replay claim.
0new functions/types/Go files; runtime+32069B (Go6728B/exampledata25341B),
tests+8295B/neworacle140934B. Capability growth, no reduction or retirement claim.
6/14Full and67/84 planning unchanged; registry.05 remains Partial.
See [proof](../evidence/fixed-inline-audit-proof.json) and
[review](../evidence/fixed-inline-audit-review.json).


Bounded sentinel reader: the existing mapper proves twelve installed protocol
words through PT_LOAD-only mappings before adding a distinct loaded sentinel_blob
interval to the shared interval projector. No program header or merged PH boundary
is invented. Dispatch recognition and physical loaded extent remain separate;
the loader byte count, two positive sector counts and entire aligned trailer must
agree. The existing audit verifies the complete stored-target window, including
tails, with explicit storage/evidence/range guards; no landing/ID fallback.
Independent36member pre-code fixture,36protocol guards/12mapping queries and
frozen native640KiBloaded versus1MiBdispatch facts verified.0new functions/Go
files;2filelevel types separate declared coordinates and observed facts. Runtime
+22088B (Go11012B/exampledata11076B), tests+12480B/neworacleJSON+ZIP57035B.
Capability growth, no reduction/retirement/milestone credit;6/14Full67/84planning
unchanged. Source-pool and other material readers remain open.
See [proof](../evidence/sentinel-reader-proof.json) and
[review](../evidence/sentinel-reader-review.json).


Pinned raw reader: existing controls validates exact span/END/one-word role
coordinates before a local surrogate pass through the shared decoder. Original
roles are restored before summaries, and authoring/native eligibility stays
blocked. Existing audit owns both side pins, bounded windows and comparisons;
existing checkJSON tracks explicit required zero-valued coordinates. No extra
parser, per-pool handler or rawcontrol report field.0new functions/Go files;
1shared fact type. Runtime+41168B (Go6164B/example35004B), tests+7582B,
neworacle47346B. Capability growth, no reduction/retirement/milestone credit;
6/14Full67/84planning unchanged. Current modified titles use ENDf800 with
internal zeroSPACE: stale NUL terminology justifies no new grammar.
See [proof](../evidence/pinned-raw-reader-proof.json) and
[review](../evidence/pinned-raw-reader-review.json).


The existing pinned reader now has33additional independently derived body cases:31
actual frozen native sides and2synthetic EN shapes. Exact normalized tokens, input
bytes, policy identity and blocked authoring checked; matrix/069 kind labels are
explicit source-backed normalization. No production/runtime changes or new functions.
Tests+1179B and oracle+315908B are evidence overhead, not code savings. Native EN
landing for matrix/069, eventselection composition and GP-relative references remain
separate.6/14Full67/84planning unchanged. See
[proof](../evidence/raw-reader-compatibility-proof.json) and
[review](../evidence/raw-reader-compatibility-review.json).


Selected event text reuses existing pointer/ELF/sentinel/stream owners with zero
production/runtime changes. Ninety static outer-row/event/pool-slot/script-header
relationships and three actual installed stream bindings verified. Both audit sides
are deliberately installed-source selfcomparison, not pristine/canonical evidence.
Outer-only metadata, wrong pointer level/slot word, missing sites and shifted
windows refuse; stale landing metadata cannot override stored pointers.
GP-relative singleADDIU observation remains the concrete reader gap;6/14Full
67/84planning unchanged. See [proof](../evidence/event-reader-composition-proof.json)
and [review](../evidence/event-reader-composition-review.json).


GP-relative observations reuse existing ELF/reference owners and existing
addiu_vma/reg recipe fields. One bounded register-info record supplies GP; exact
ADDIU source/destination bits and signed arithmetic determine observed targets.
Unknown metadata retains readable words and errors; no landing/ID fallback.
Three portable full rows,14guards and8instruction vectors plus native9IDs/10sites
and8whole bodies verified. ZeroGP is known; missing/duplicate/short metadata is
unknown. Shared labels/nullchecks are not separate display ownership.0new
functions/Go files;1shared fact type. Runtime+14278B (Go3540/example10738),
tests+4495/neworacle64662 reported separately. No savings/retirement/criterion
credit;6/14Full67/84planning unchanged pending rootassessment. See
[proof](../evidence/gp-reader-proof.json) and [review](../evidence/gp-reader-review.json).


The material reader checkpoint is proven: registry_reconciliation.05 adds one
planning credit, bringing the checklist to68/84(80.95%). Full families remain6/14;
registry reconciliation remains Partial at5/6. This covers identified bounded
reader forms and explicit unknowns, not all410 paths, pristine context, runtime
selectors, gameplay or patch authority. Joined proposals remain separate.
No production/runtime/test changes or savings. See
[assessment](material-reader-milestone-assessment.json) and
[challenge](../evidence/material-reader-milestone-review.json).


Reviewed pointer-stream reconciliation extends the existing audit owner: explicit
current-pin review plus exact canonical bytes, zero observed tail and complete
reference/window proof can suggest machine status and actual observed landing.
Unknowns/holds/progressed states stay visible; human wording and attribution are
never rewritten. Unchanged means no status promotion, not allmetadata equality.
Inline machine policy remains held.0new functions/Go files;2shared facttypes.
Runtime+19132B (Go4348/examples14784), tests+6047/oracle62614separate.
No savings/retirements/newcredit;6/14Full68/84planning unchanged. See
[proof](../evidence/joined-reconciliation-proof.json) and
[review](../evidence/joined-reconciliation-review.json).


Inline16 machine proposals reuse the pointer decision owner after the original
field-location policy was independently confirmed. Both complete16byte maps,
plain glyph/control validation, literal canonical padding, currentstatus and
review remain required. Landing means verified fieldlocation, not a stored glyph
pointer. Explicit pointer_vma key presence (includingempty/null) holds proposals
without changing existingunreviewedreadfacts.28independentrows/8reviewcases,
2proposed25held1unchanged, existinggeometryrefusals andfreshLOWclosure verified.
0newfunctions/types/Go/runtimefiles; runtime+1859B(Go523/data1336),tests+966/
oracle+6933separate.6/14Full68/84planning unchanged pendingcriterionassessment.
[Proof](../evidence/inline-reconciliation-proof.json) and
[review](../evidence/inline-reconciliation-review.json).


## Reconciliation and reporting closure — 2026-10-21

The [root assessment](joined-capability-milestone-assessment.json) awards exactly
two frozen .06 checkpoints and promotes these two original families after the
[independent source challenge](../evidence/joined-family-assessment-review.json)
and [fresh behavior review](../evidence/structural-audit-review.json).
The existing Go audit now emits source-accurate structural facts, including
reference-relative headerless warnings and explicit unknowns. Four existing
commands compose around pinned inputs and complete declared selection.
Runtime grows3695B; no functions or runtime files were added. Tests grow5414B;
the new fixture is49605B after28480B of unused metadata was removed.
The84113B replay bundle is executed evidence, separate from runtime. No code
reduction, historical-script retirement, installed/native fit or gameplay claim.

## General GP indexing — 2026-10-21

The [root assessment](gp-index-milestone-assessment.json) awards only
`binary_inspection.04` after the [fresh review](../evidence/gp-index-review.json).
The family stays Partial4/6; Full coverage remains8/14. Shared source-window
classification/indexing is broader than metadata backfill, while live GP, loaded
pointers, CFG and hook safety remain explicit unknowns. Production grows11,344B;
runtime including the612B example grows11,956B. No functions/Go files or historical
retirements were added. Tests/fixture/evidence overhead is separate.


## Finite instruction facts - 2026-11-04

The [shared index proof](../evidence/instruction-flow-proof.json) and
[fresh review](../evidence/instruction-flow-review.json) verify local operand and
control facts through existing owners. Binary inspection remains4/6; the planning
index stays71/84 and Full coverage8/14. Branch listings do not perform the original
source reaching-def/use duties. Production grows15,204B and runtime15,564B;
no function or historical retirement was added. Tests/fixture/evidence are separate.


## Bounded register graph - 2026-11-04

[Proof](../evidence/register-flow-proof.json) and [final review](../evidence/register-flow-final-review.json) verify actual shared graph queries, not full original caller coverage. Full coverage stays8/14, planning71/84 and binary inspection4/6. Production grows13,458B and runtime14,296B, including one justified pure function; tests+3,916B and ZIP8,475B are separate. No net reduction or historical retirement. Unknown reentry holds backward completeness; forward definite kills can close an earlier value.


## Shared registry ownership diagnostics - 2026-11-04

[Proof](../evidence/reference-owner-proof.json) and [final review](../evidence/reference-owner-final-review.json) verify the fresh-ELF graph and registry ownership join. Full coverage stays8/14, planning71/84 and binary inspection4/6. Production grows21,781B and runtime25,213B; tests+14,304B and ZIP14,518B are separate. The16,137B producer extraction is relocation. No net reduction, historical retirement or full .05 claim. Original reads_arg/Tracerconsumer and interior/hookABI duties remain.


## Shared fixed permission data - 2026-11-05

[Proof](../evidence/permission-resource-proof.json) and [review](../evidence/permission-resource-final-review.json) verify shared permission acquisition through existing render owners. Two native profiles share one canonical table. Thirteen rectangles reproduce all80254 fixed source pixels, without a new geometry engine. Production grows2834B and runtime3398B; tests9860B/ZIP734B separate,0newfunctions/types/retirements. Full8/14, planning71/84, raster5/6 stay unchanged.


## Shared source-pixel masks - 2026-11-05

[Proof](../evidence/mask-pipeline-proof.json) and [review](../evidence/mask-pipeline-review.json) verify two shared numerical owners: current erase selection and original permission footprints use one predicate constructor; erase growth, font counters and source footprints use one four-connected topology implementation. Seven asset-keyed permission tables carry facts.179originalsourcevectors plus3shifted observations pass in core and native-font builds; the reviewer independently checked14179numericassertions and46CLIprobes.

Production grows14246B and runtime28042B; tests19437B/fixtures157572B separate,2newfunctions/4types/0retirements. Extraction is relocation; new source capability is growth. Full8/14, planning71/84, raster5/6 stay unchanged. Other27providerrecords, donor acquisition, advanced reconstruction, fields, radial and source-art/material responsibilities remain open.


## Shared component filtering - 2026-11-05

[Proof](../evidence/component-mask-proof.json) and [review](../evidence/component-mask-review.json) verify size, foreground seed membership and whole-component tag veto in one existing traversal. Four/eight component membership stays separate from four-neighbor morphology. Explicit sampling bounds allow source cropped selection followed by whole-canvas growth. Seven additional provider records have14actual and16manual original masks; existing replay now covers209sourcevectors plus33shifted observations.

0newfunctions/1type/0newGofiles. Go and runtime grow5108B; tests9932B/fixture66388B separate. No reduction, retirement or family credit. Full8/14/planning71/84/raster5/6 unchanged. Complete source global contexts retain flood operands; those and remaining reconstruction/art duties remain open.


## Shared flood permissions and complete source contexts - 2026-11-05

[Proof](../evidence/flood-mask-proof.json) and [review](../evidence/flood-mask-review.json) verify six flood calls and56stage results for four complete permission contexts on synthetic original pixels. Existing component/hole-fill/erosion owners handle label-zero background and post-union crop erosion. Three tables serve four stable asset IDs; two identical assets share one table. The obsolete476Bpartial runtime table is deleted, with historical expectations preserved.

0newfunctions/types. Go grows1573B/runtime8670B; tests8408B/fixture152220B separate.297sourcevectors plus121shifted observations pass in core/native builds. Astra044 ownership and maintenance-gate documentation findings are closed through one panel authority, five prefix checks and the existing combined CLI/Golden command. Full8/14/planning71/84/raster5/6 unchanged; art/hooks/text/donor/advanced reconstruction remain open.


## Ordered source codec - 2026-11-05

[Proof](../evidence/ordered-text-proof.json), [independent review](../evidence/ordered-text-review.json) and [original-scope assessment](ordered-text-family-assessment.json) close text_codec.05/.06. Shared encode/controls/wrapPages preserve one ordered control tape, full eight-byte payloads and declared prefix/pair/speaker roles under changed wording and exact no-ops. Actual plan/guarded copy, fit and audit callers retain their safety boundaries.

111 core and real-audit cases (83 positives,28 refusals) pass at source origins0/6 in core/native builds. Post-guard race, build/vet/format/scoped hygiene pass. A late duplicate-prefix-speaker override defect was independently reproduced, fixed in the existing preparation owner and closed by four new refusal cases. One local occurrence record resolves Astra045 bookkeeping duplication. No new function or handler was added.

Full9/14(64.29%), planning73/84(86.90%). This adds capability and code, not script retirement or net reduction. Unknown native widths/opaque image writes, unclassified narrative E000 varargs and multi-rune authoring remain explicit separate domains. No full-suite/nativefonts-race/gameplay claim.


## Shared registry draft admission - 2026-11-05

[Proof](../evidence/registry-import-proof.json), [review](../evidence/registry-import-review.json) and [contract](../analysis/registry-import-contract.json) verify four declared JSON/CSV draft policies through the existing owner. Source policies intentionally differ; binary controls are not a lexical-import parser. Pinned input roles, normalized whole-cohort IDs, raw metadata/numbers, exact all-present bytes and the exclusive publisher are shared. CSV field spans preserve quoted CRLF after standard-library grammar validation.

The shared JSON rewrite branch now checks the complete compact document before indentation, including inherited metadata; all rewritten snapshots fit 64 MiB. The estimate conservatively overcounts empty containers. CSV provenance is capped at512 UTF-8 bytes, retaining the original 282-byte label. Independent review found and root closed both multiplication risks. Whole outputs for author/merge/add/markup match accepted718;33 deep rows match66,538,175 bytes,34 refuse, and deep inline/import no-ops retain75,133 source bytes. No hostile-memory sandbox is claimed.

Runtime grows; no function or per-script handler was added. Coverage remains 9/14, registry 3/6, planning 73/84 and410 retirements unchanged. Fixed constructor facts, missing selection/occurrence source bindings and glossary/correction/drift reconciliation remain separate work. Full suite/nativefonts race/gameplay stay deferred.


## Paired registry corrections and glossary - 2026-11-05

[Proof](../evidence/registry-paired-proof.json), [review](../evidence/registry-paired-review.json) and [contract](../analysis/registry-paired-contract.json) verify the first paired .06 slice. One fixed operation consumes three pinned roles and stages the complete pair. Existing EN/note mutation and an ordered document loop retain readable serialization, metadata and exact numbers. Fully authored suffixes keep historical wording in data; already-applied rows never append again. Held rows allow independent glossary advancement; stale or conflicting data refuses everything.

The ZIP contains exactly registry.json and glossary.json, deterministic Store members, closed before the existing exclusive publisher runs once. Successful return verifies a complete artifact; the pathname is visible during writing and no canonical files are installed. Unchanged members retain exact bytes/dates, deliberately improving old date-rewrite behavior. Independent50fixtures, emitted-member replay, typed/wire/source-profile/budget refusals and old route tests pass. A resulting-glossary count bug found in review is closed at the existing append guard: the final slot succeeds/replays, one extra term refuses.

No new function or runtime file was added. This is capability growth, not a code reduction or script retirement. Coverage remains9/14, registry3/6, planning73/84. Human drift/force and decoded-flow/source construction remain separate unfinished responsibilities. Full suite/nativefonts race/gameplay remain deferred.


## Human source and field ownership - 2026-11-05

[Proof](../evidence/registry-human-proof.json), [review](../evidence/registry-human-review.json) and [milestone crosswalk](../analysis/registry-ownership-milestone.json) close registry .06. Registry progress is4/6; the planning index is74/84 (88.10%). Core families remain9/14 (64.29%), with no script retirement or code-reuse percentage claimed. Per-pool .04/.05 duties remain.

One justified pure source resolver joins decoded winners, flow scope and named authored fields. Registry status/mutation/noop/serialization/publication stay with their existing owner. It shares insertion only for missing rows; matching, locked and drifted rows still refresh metadata. Human force never changes locked wording and only known unlocked statuses permit actual wording replacement. Selected-only metadata checks preserve unrelated incomplete records; this and unchanged-byte/date behavior deliberately differ from the old writer.

Separate tables capture62human entries,52complete correction intents and17glossary proposals. Literal annotations and the deliberate no-fix Doom row require no term/date formatter or per-script handler. Real62source semantic parity and controlled52/17state comparisons pass; complete Go replay preserves bytes/date. Current applicability of historical corrections and native/gameplay readiness remain unproved.

This increment adds one production file and one function for a distinct source relationship, plus two shared value types. Combined code/module/data accounting grows by97397B (224runtimefiles/2792590B). This is capability growth, not deletion or a reduction. Test and fixture overhead are reported separately in the proof. Full suite/nativefonts race/gameplay remain deferred.


## Registry pool responsibilities - 2026-11-05

[Proof](../evidence/registry-pools-proof.json), [review](../evidence/registry-pools-review.json) and [original-scope assessment](../analysis/registry-pools-family-assessment.json) close registry .04/.05 and its material family contract. Registry is6/6, core families10/14 (71.43%), planning76/84 (90.48%). This measures verified toolkit responsibilities, not code reuse or historical script retirement.

The existing admission owner gains the finite full_sweep policy. It checks ten required fields and the source speaker/page/glyph/apostrophe rules. Exact decoded-text hashes bind reviewed complete one-based EN-ordinal to JP-source-position marker permutations; no note substring grants a waiver. Kind-only default validation retains an explicit source weakness. This proves lexical admission, not opaque native argument bytes.

Separate data holds142 original constructor facts, five marker mappings and five complete note replacements. The six historical keeper decisions are represented by current normalized source facts. Legacy raw temporary inputs are absent, so their preselection replay is not claimed. All3186 current batch rows match independently frozen original whole-document expectations. Evolved current wording conflicts refuse historical constructor application.

No production file or function was added. Go grows4488B; code/module/recipe/runtime inputs together grow184978B to233files/2977568B. Tests grow5543B and fixture/configuration inputs64795B separately. This is capability growth, not a reduction. The golden pin verifier now distinguishes exact disjoint profile/resource roles and retains all56 prior hashes. Fullsuite/nativefonts race/gameplay remain deferred.


## Square permission masks - 2026-11-13

[Proof](../evidence/square-mask-proof.json) and [independent review](../evidence/square-mask-review.json) verify three batchE permission calls on two declared synthetic contexts (six provider comparisons). Existing mask owners gain one optional cross/square morphology setting; hole filling stays four-connected and component connectivity remains separate. Button crops remain separate, and full-canvas sale protection clips to its own sign after growth. The old implementation failed the independently frozen sale mask before API edits. All three runtime tables now supply the complete-mask test, with unchanged source bytes.

Go grows1265B with no new function, production file, type or dependency. Code/module/recipe/runtime inputs together grow9309B to236files/2986877B. Tests grow8736B and fixtures31096B; the110267B source archive is separate evidence overhead. This is capability growth, with no deletion or reduction claim. Core10/14, planning76/84 and raster5/6 remain unchanged;17other Epermission calls and advanced artwork duties remain. Source masks do not prove actual game art dimensions or complete rendering hooks. Fullsuite/nativefonts race/gameplay remain deferred.


## Named approved fixed artwork - 2026-11-13

[Proof](../evidence/fixed-art-proof.json), [fresh pre-apply reviews](../evidence/fixed-art-reviews.json) and [maintenance contract](../docs/fixed-art.md) establish one source-bound allmap_1 logo-A replay through the existing static PNG importer. The canonical versioned record owns approval/provenance and independent whole-native/RGBA/mask facts, with one profile owning operational fields. Shared source/image/mask PNGs remain readable data. The two concrete reviews preceded the exclusive standalone native write; every263584byte matches the old independently approved target. WholeRGBA/11570mask/11027changedpixels/outside0 and unchanged CLUT/nonpixel data were checked separately.

No production Go function, file, field, type or dependency changed. Runtime data grows1465122B to241files/4451999B; tests grow11659B and fixtures180506B separately. This is data/workflow growth, not a new generator or reduction. Exact-target and hole-mask checks are external to the runtime coarse rectangle/self-integrity guards. In-memory maintenance counterexamples demonstrate that repinning an edited image requires a new approved version and independent expected artifact. Original14/84/410history, unsupported editable generators and core10/14/planning76/84/raster5/6 remain unchanged, with no retirement credit. No ISO, live artwork or public main change. Broader fullsuite/nativefonts/race/gameplay were not repeated for unchangedproduction/staticPNGdata.


### Root-inclusive dependency queries - 2026-11-13

The [root-inclusive query](register-inclusive-contract.json) extends the existing
forward traversal. [Verification](../evidence/register-inclusive-proof.json) grants
no milestone credit: binary4/6, overall10/15 and76/90 remain.


Current bounded extension: [pointer consumers](pointer-consumer-contract.json) reuse the same instruction producer and CFG for origin aliases, spills and typed consumer events, with explicit unknown continuation/loss. [Proof](../evidence/pointer-consumer-proof.json) records growth and source corrections; full families10/15 and checklist76/90 are unchanged. [Retired static ELF design](retired-static-elf-design.json) is separate from verified Go. Current native ink/layout tooling is next; probe remains last.


### Native source-grid ink - 2026-11-13

[Optional atlas measurements](native-ink-contract.json) extend existing fit owners.
[Verification](../evidence/native-ink-proof.json) supports a partial literal/control
slice, with numeric ink unknown. Coverage remains 10/15 and 76/90; consumer layout 3/6.

The [source-bound nominal cohort report](name-cohort-contract.json) is now available through existing source, scanner and graph owners. The [synthetic example](../examples/name-cohort/README.md) is runnable, while the [proof](../evidence/name-cohort-proof.json) separates final affected checks from dated v1 broad/race evidence. There are 43 cases and 28 typed refusals, including 26 unique measurement inputs and two raw-cap boundaries. No actual current game census, alias, landing, native fit or migration credit is claimed.

The [synthetic name-policy replay](../examples/name-policy/README.md) expresses eleven dated F172/F173 records through existing guarded words. Complete synthetic readback is verified; native/source/ownership/fit acceptance remains separate. Production Go is unchanged, no reduction or credit is claimed, and probe work remains last.

### Current finite F112 criterion closure

The [canonical acceptance](../evidence/name-policy-replay-proof.json#accepted_finite_f112_criteria) supersedes earlier held criterion summaries while preserving their historical evidence. Independently reviewed native maintenance and source-qualified allocation derivation close consumer_layout.04 and image_layout.05. No compiled/native proof was rebound to the parked range candidate; its whole CLI test remains unexecuted. No new production/runtime/test implementation or native operation accompanied this metadata-only closure.

The separate [native-ink assessment](../evidence/native-ink-proof.json#current_criterion_assessment) now closes consumer_layout.05. Its22synthetic native-format ink goldens/22legacy reports are distinct from actual native codec/source qualification; no combined actual-atlas+metric text report was performed. The current index is79/90; consumer5/6,image5/6 and10/15Full. Numeric/scaled/FPU/physical-fit and .06geometry claims remain excluded.

### Conditional consumer diagnostics completion (dated80/90)

Consumer layout is now6/6 Full under the [reviewed source-qualified contract](consumer-layout-facts.json#current_conditional_diagnostics_assessment):80/90 criteria and11/15 Full families. Positive conditional geometry and independently expected plain-child measurements share existing tools. They do not establish runtime viewport/index/gender closure, arbitrary A000 authoring, physical/vertical fit or ABI. Frozen selector-ID/advance and width-zero-reset corrections are explicit. The original A000 parent stays unsupported; prior source/compiled/native proof pins and the parked range candidate are unchanged. Ten rows retain zero credit: six probe-last, three active original-tool and one reviewed retired disposition.

Dated binary.05 acceptance was5/6 after the [finite consumer criterion assessment](../evidence/register-flow-proof.json#current_criterion_assessment):81/90 overall,11/15Full. Source-proved external bridges and local Go low32 observations remain distinct, with no automatic128bit/interprocedural inference, fullTracer parity or ABI claim. binary_inspection.06 is planning only; probe remains last and range wholeCLI is stale/unexecuted.

The [finite hook/interior assessment](../evidence/register-flow-proof.json#current_hook_criterion_assessment) completes binary6/6 Full:82/90 criteria and12/15Full families. Source-matched8B RA/helper/translator guards remain external to low32 Go facts; strict definitions retain UNKNOWN and GP is metadata-conditional. This synthetic contract is not native/fullABI/globalRefs/128bit/gameplay proof or a new intrinsic CLI ABI refusal. Unused range removal awaits scoped pre-edit review before raster.06 planning; probe remains last.

### Current raster completion (83/90)

[The accepted assessment](../evidence/reconstruction-row-proof.json#current_raster_criterion_assessment) supersedes earlier partial raster summaries. Current totals are83/90 criteria and13/15 Full families; production core remains49files/672636B/47functions. One native replay is not203 replays. The next named criterion is probe.01, retaining exact production identity/nonce/path/refusal semantics; runtime handover and native acceptance remain separate.

Current accepted status is85/90,probe2/6,13/15 Full. The [saved-evidence report assessment](../evidence/probe-records-proof.json#current_report_criterion_assessment) preserves exact source comparison/ordering/unknown boundaries. This supersedes earlier probe-zero/one summaries; .03-.06 remain uncredited.
