# Dokapon Go tools

A registry-driven Go replacement for the historical Python patch tools. Canonical
English stays in the registry; separate recipe tables hold patch facts. Read
[MIGRATION.md](MIGRATION.md) for coverage, current evidence, costs and remaining work.
Resume the persistent goal from [.goal/GOAL.md](.goal/GOAL.md).

The current [v3 coverage](analysis/reusability-coverage.md) is **13/15 fully verified core families (86.67%)**, with two Partial and none Unsupported. The [granular roadmap](analysis/migration-roadmap.md) exposes all **90 acceptance groups: 85 proven (94.44%)**, six per family. Probe orchestration and evidence is Partial with **2/6** groups proven in Go. These are capability/checklist counts, not code reuse, effort, time or script migration percentages.

The original14 authoring families retain their scoped usable operations. The new full probe workflow has no verified Go orchestration owner. Existing Python remains the sole production owner until identical native acceptance and explicit handover. Starting a story probe, unattended crash/stall detection, bounded recovery, safe stop/resume, preservation and bounded evidence/resource use are required. The probe owner must agree the soak duration, recovery outcomes and budgets before acceptance; earlier three-story tests do not prove unattended acceptance.

The [v1 baseline](analysis/reusability-coverage-baseline.json) remains byte-identical. Its accepted808 views preserve **10/14 Full (71.43%)**, **76/84 (90.48%)** and expanded **10/17 (58.82%)** as history. The original three optional runtime groups are retained as non-additive facets of the one new core family, so v2 introduced 15 unique families, which v3 retains. Native hook/counter/ABI duties and fixed-field, narrative, positional-grid, code/hook/capacity and image-state scenario duties remain in scope. No Go/runtime implementation, new native proof, retirement or capability credit follows from this taxonomy update.

Raster rendering is6/6 under the [accepted current fixed-data contract](evidence/reconstruction-row-proof.json#current_raster_criterion_assessment): one exact native replay, a separate editable donor/order witness and203 source-bound material dispositions. This does not claim203 native replays, arbitrary generators, pristine provenance or gameplay acceptance.

The [offline probe proof](evidence/probe-records-proof.json) accepts saved-record admission `.01` and saved-evidence reports `.02`. Reviewed `--probe-sequence` software now runs three immutable recipes through controlled creation, overwrite and alternating File1/File2 checkpoints, with verified terminal cleanup and postflush card carry. Four offline checkpoint memberships and three story50 observations pass the independent literal oracle. This is not native stories, broader producer coverage, owner resource/soak agreement or handover. The score remains **85/90**, probe **2/6**; `.03`–`.06` remain uncredited. See [the bounded contract](docs/probe-records.md) and canonical `sequence_offline_assessment`. The opt-in source-qualified storage observation acquires one fixed field through existing shared owners; it is non-atomic and supplies no displayed-UI or checkpoint credit. One stored narrative-body row now shares stream controls and the existing normalizer, with A000 expansion opaque and no additional credit.

Follow [AGENTS.md](AGENTS.md): inspect symbols and callers with Serena, enhance
existing functions whenever reasonable, and verify the complete change.

For maintainability, group code around decisions that can change independently,
keep patch facts in recipes, and preserve a clear path through validation. This
applies [Parnas's information-hiding criterion](https://www.cs.lafayette.edu/~gexia/cs301/resources/parnas.html),
rather than using file length as the design criterion. A
[naming experiment](https://brains-on-code.github.io/descriptive-compound-identifier-names.pdf)
supports informative domain names, but its Java defect-finding results do not
establish a Go naming rule. [Complexity research](https://arxiv.org/abs/2007.12520)
finds useful correlations alongside mixed results: use metrics to guide review,
then check behavior, change scope and whether a developer can follow the code.

## Build and run

From the repository root:

```sh
go -C tools/go test -race ./...
go -C tools/go vet ./...
go -C tools/go build -o /var/tmp/dokapon-go-tools .
/var/tmp/dokapon-go-tools \
  --source iso/original/original.iso \
  --registry registry/string-registry.json \
  --glyphmap extracted/glyphmap.json \
  --recipes tools/go/recipes
```

This command performs a read-only plan for the three immediate pristine-image
tables: four same-length streams, 100 rename fields and 60 nickname fields. A recipe
directory loads only its immediate `*.json` files. Select nested stages separately.

Applying adds `--apply --output /new/path.iso`; the output must not exist. The writer
replans, verifies the complete source hash, creates an exclusive copy, guards old
bytes and verifies readback. Real-image work also requires two fresh independent
ordinary reviews and an independent whole-image comparison. Original, shipping,
custom-art images and the canonical registry remain read-only.

The verified latest-mod build has one entry point from the repository root:

```sh
tools/go/build-current.sh iso/original/original.iso /new/current-mod.iso
```

It builds the Go runner, composes allocation with the existing loader-code
table, replaces the named executable from a pinned ZIP, then reuses the 142
CMB member facts. Each stage checks its source; the last two enforce the full
output hash and remove their new copy on mismatch. The verified output is
`49ab69ace2de5575dea17c3939d0f24280b03a05fb794b525a5ad4dab0041010`.
Two fresh independent reviews cleared the pinned inputs before the
[actual isolated build](evidence/latest-build-proof.json). Every output byte
matches live49ab69ac; all4,173,391 changes from the original lie within150
declared edits merged into26intervals. Independent full-image readback verifies
original/shipping hashes and unchanged registry/glyph inputs. No Python runtime
or historical patch script is part of this build.
The prior [actual build proof](evidence/current-build-proof.json) confirms every byte
of the 4,243,259,392-byte output equals the frozen `817962e2` shipping version,
with zero unexplained changes. Shipping advanced to `49ab69ac` on October19;
the [read-only delta](analysis/live-vs-frozen-baseline-delta.json) accounts for
all1,602 additional changed bytes. The prior build's exact script is retained
as executed evidence in `evidence/build-current-817962e2.sh`.
Two fresh independent reviews cleared the exact build inputs before the run;
original/shipping images and canonical registry/glyphmap hashes are unchanged.

This is a frozen compiled baseline. It reproduces embedded modifications but
does not make them individually editable or retire historical tools. Subsequent
registry-driven changes need recipes bound to this baseline's real preimages.
Held semantic recipes remain held even when their shipped bytes occur in the
frozen executable. Python and historical patch scripts are not build inputs.

## Reusable toolkit direction

For two pinned PNGs, the existing texture entry point produces a comparison:

```sh
go -C tools/go run . --source examples/asset-comparison/before.png \
  --texture-profile examples/asset-comparison/profile.json
```

This example stretches the unequal after image to the before image's geometry.
`preview.scale` is a positive integer; optional `preview.crop: [x,y,w,h]` applies
to both inputs, with transparent padding outside their bounds. Each scaled panel
gets its own 8-pixel checkerboard and the pair has a 6-pixel gap. Add
`--apply --output /new/comparison.png` to publish a new RGB PNG. Sources stay
unchanged. Input/crop is bounded to 1M pixels, each panel to 16M, and the complete
canvas to 32M; publication also has a 128MiB encoded bound. This presentation
operation does not approve artwork or patch the game.

Two further layouts use the same comparison operation:

```sh
go -C tools/go run . --source examples/asset-comparison/before.png \
  --texture-profile examples/asset-comparison/flat-profile.json
go -C tools/go run -tags nativefonts . \
  --source examples/asset-comparison/weekday-before.png \
  --texture-profile examples/asset-comparison/weekday-profile.json
```

`preview.layout` defaults to `checker`. The `flat` layout crops both inputs to
shared XYWH bounds, pads unequal inputs, and scales a four-source-pixel gap on
90 gray. Its opaque output retains an RGBA PNG header. With no crop it uses the
before image's full extent; it does not stretch the after image.

The `weekday` layout uses the fixed crop and caption positions in the separate
[pair layout table](profiles/previews/pair-layouts.json). It paints pinned
Aileron BASIC captions and strips on a 336×160 RGB page, then scales the complete
page with nearest sampling. `preview.font` uses the existing `path`, `size`,
`sha256` pin shape and is required only for this layout. It needs the optional
native font build; flat and checker layouts retain the default build. Captioned
whole-page output is bounded to 16M pixels. Both examples accept
`--apply --output /new/pair.png`, recheck their inputs and create an exclusive file.

Labelled inventory pages consume one or more pinned manifest bundles:

```sh
go -C tools/go run -tags nativefonts . \
  --source examples/asset-contacts/source.zip \
  --texture-profile examples/asset-contacts/profile.json
```

This synthetic example was exported by the existing manifest operation. It returns
13 inventory rows, including unavailable entries, and two labelled pages. Add
`--apply --output /new/contacts.zip` to publish pages, preserved PNG previews,
`inventory.csv` and a JSON report together. Additional bundles belong in
`contacts.sources`, using the existing `path`, `size`, `sha256` pin shape. Paths
resolve relative to the profile; the primary source retains the CLI's path rules.

Styled text uses the same cell compositor for grayscale atlases and TrueType.
The [TrueType tutorial profile](profiles/textures/help00-turn-order-ttf.json)
selects a [shared font manifest](fonts/noto-condensed-extra-bold.json), whose
`truetype` source has `path`, `size`, `sha256` and a `layout` of `BASIC` or `RAQM`.
The font path resolves relative to its manifest, and the manifest path relative
to the texture profile. Run it on a pinned extracted standalone TXD:

```sh
go -C tools/go run -tags nativefonts . --source /scratch/original-help00.txd \
  --texture-profile profiles/textures/help00-turn-order-ttf.json
```

Add `--apply --output /scratch/new-help00.txd` for an exclusive new output.
This operation preserves whole-run kerning at zero tracking and the original
per-character rendering when tracking is nonzero. An omitted `layout.strokes`
selects the scalar default; explicit `[]` means no stroke for TrueType. Bitmap
fonts retain their existing stroke constraints. Omitted cell `background`
preserves input pixels; `background_rect` requires an explicit paint color.
TrueType retains the original fixed temporary-canvas crop before common styling;
final word-layer ink and complete icon rectangles must still fit the approved cell.
The exact font and its OFL notice are in `fonts/noto`. The example is scratch
authoring, with no artwork, gameplay or ISO-placement approval.

Reconstruction uses the same compositor, native importer and exclusive publisher.
The [donor-only example](profiles/textures/help00-reconstruction.json) needs no
font or native-font build tag. Its `render.permissions` pins a shared table of
`allow`, `exclude` and `allow_add` rectangles; `render.reconstruction` keeps the
identified local `erases`. The resource path is relative to the profile, with an
exact size/SHA-256 and a1MiB cap. Existing inline permission arrays remain valid
when the shared resource is absent; the two forms cannot be combined.
Permissions are the union of allow rectangles, minus exclusions, then additions;
each rectangle is XYWH.
Erases select current pixels with optional `lum_lt`, `lum_gt`, or RGB `near` /
`tol`, grow through four neighbors, then apply `flat`, `clear`, `rows` or `cols`.
Row/column donors come from outside the final hole within that erase's crop;
endpoints clamp and donorless lines remain unchanged. Colors retain straight
RGBA, including hidden RGB at zero alpha. Empty selections bypass method and
fill validation, matching the original behavior.

An erase's root selectors and every entry in `all` combine with AND. Each of
at most32 extra clauses has its own `tol`; `near` includes equality and
`not_near` excludes that same RGB cube. Alpha does not affect color distance.
`sat_lt` compares the largest RGB channel minus the smallest. Clauses share
current-pixel reads and upfront validation; the existing grow, donor and write
path is unchanged. The original logo OR grammar and morphology remain held
separately. The [two-exclusion example](profiles/textures/help00-color-exclusions.json)
uses the same font-free CLI and separate recipe facts.

Mixed text and erases require `render.order` to name every unique step ID once.
Text reads the current working canvas; icons copy the immutable original.
Each text step must preserve final bytes outside the exact permission mask.
The rectangles passed to native import are coarse guards, not the exact mask.
Other reconstruction algorithms remain outside this finite primitive. The
example is a scratch exercise on pinned original pixels, not historical artwork
migration, visual approval or full raster-family coverage.

The default build retains the existing tools without native font dependencies.
Labelled contacts require Linux, CGO, a C compiler, FreeType development headers
and `pkg-config`, plus the `libraqm.so.0` runtime. Build with `-tags nativefonts`;
without it, TrueType authoring and contacts refuse with an actionable error. This backend calls installed
libraries directly; Python is a reference only. Exact font bytes and their notices
live in `fonts/preview` and `licenses`. Current pixels are calibrated against
FreeType2.14.3, Raqm0.10.1 and HarfBuzz14.1.0; other builds need the focused goldens.
FreeType is provided by [the FreeType Project](https://freetype.org/).

Collection order is preserved before group-local duplicate removal and stable
archive/index sorting. UI rows retain duplicates; the other groups remove them
before sorting. Later groups can replace a shared preview's page link. CSV then
propagates the first linked pixel key in input order. The retained legacy key is
12 hexadecimal SHA1 characters of raw RGBA bytes, without dimensions; it is a
display deduplication rule, separate from the SHA256 integrity pins. Missing or
empty source pixel hashes do not deduplicate. Failed and unmeasured rows remain
in the inventory. Scores and flags come from the pinned input reports, not OCR.

Each source/member is measured once; thumbnails are computed once on first use.
Grid geometry, colours and font layout are in the separate
[layout table](profiles/previews/inventory-layout.json). The resampler owns
no-upscale thumbnail sizing and exact filtering; the font backend owns complete
label masks. Captions preserve blank and trailing lines, clip to the whole page,
and paint immediately after their thumbnail so later items cover earlier ink.
Publication rechecks every
bundle, font and profile before creating one exclusive output. Bounds include
256MiB input/expanded ZIP data,100000 rows,256M decoded/page pixels,16M cached
thumbnail pixels and128MiB output. The pair layouts above are implemented;
the [final contact proof](evidence/asset-contact-score-policy-proof.json) closes
the original preview/inventory contract. Evaluated detector failures retain null
scores but can produce pages, displaying the original -1 glyph/0 line fallback.
Imported absent detector records use `not_evaluated` and blank measurements; a
declared duplicate pixel key can still inherit a page link. Headerless PNG views
use measured dimensions with depth0 while native header metadata stays null.
Stable-ID JSON, decoded statuses, ZIP-relative links and LF CSV are intentional
normalized views; historical serialized bytes are not promised. Full migration
and gameplay remain separate.

The shared image resampler supports explicit LANCZOS for existing authoring and
NEAREST for previews. NEAREST preserves straight RGBA, including hidden RGB,
and can sample a cropped view with transparent padding outside the source.
Thumbnail variants preserve aspect ratio with the original floor/ceil error rule
and never enlarge the source. Preview output has a separate16M-pixel/16384-axis
bound; existing LANCZOS limits stay unchanged.

The [410-source pattern crawl](analysis/pattern-crawl-verification.json) informs
[a small capability-based toolkit](analysis/reusable-toolkit-plan.json), rather
than one replacement per old script. Current reusable mechanics remain below.
The read-only authoring prototype accepts new registry wording and a separate
consumer profile, without target pins, patch locations or complete reference
topology. From this directory, using the verified frozen scratch image:

```sh
/var/tmp/dokapon-go-tools \
  --source /var/tmp/dokapon-go-current-proof-jj1ik_5k/current-mod.iso \
  --registry evidence/fit-prototype-wording-input.json \
  --glyphmap ../../extracted/glyphmap.json \
  --fit-profile profiles/fit/village-dialogue.json
```

The JSON report contains generated bytes/hash, per-line/page native pen widths,
declared limits, overflow diagnostics and explicit unsupported results. Set a
box's `wrap` to use the existing formatter with measured advances; omitted/false
measures literal LINE/PAGE placement. No-page boxes retain all automatic lines
on their original page and report excess height. Long words remain intact and
can overflow. Source/font and glyphmap pins remain required. Apply/output/recipe
flags are refused. The example profile is a static398-unit/three-line candidate,
not final visual geometry; its source pin deliberately rejects the newer live ISO.

For source-grid ink measurements, add optional `ink_atlas` using the shared
`RegistryInput` keys: `path`, `size` and `sha256`. The path resolves relative to
the fit profile and selects one standalone native font TXD. Existing
[font-atlas authoring](profiles/textures/font-atlas-export.json) uses this resource
format. The decoder requires named `font0`, `font1` and `font2` pages; physical
order does not select a page. Candidate ELF metrics and atlas hashes are separate
measured inputs, with no installed-pairing claim.

Rows then add `ink_status` (`measured`, `known_empty` or `unknown`) and, when
known, half-open `ink_bounds_by_page` arrays `[left, top, right, bottom]`. Bounds
include every nonzero-alpha pixel of the full glyph tile, placed using its native
bearing. Y is local to each line's tile, and SPACE draws no ink. Numeric or nested
substitutions leave the whole row's ink unknown, including later literal origins.
`within_profile` still describes pen/count/byte checks. These bounds do not prove
physical clipping, scale, positioning or actual screen fit. See the
[contract](analysis/native-ink-contract.json) and [checks](evidence/native-ink-proof.json).
Omitting `ink_atlas` preserves the existing report format.

A fit entry can supply `authoring` (`markers`, `plain`, or `ordered`) together
with `source: {"start": "0x100", "end": "0x110"}`. These are byte offsets
relative to the selected ELF, including when `iso_file` selects it from an ISO.
The aligned range must contain exactly one bounded narrative stream through END.
The existing source and glyphmap pins cover it. Encoding can succeed and return
bytes while native measurement reports `unsupported` for opaque arguments,
scale or position controls. A zero width in an unsupported row is not a fit result.

For menus whose choices depend on LINE controls, set a box's
`required_line_breaks` to an exact count, including trailing breaks. Explicit zero
requires no LINEs; absent/null leaves the count unconstrained. Such boxes cannot
enable `wrap`. Successfully measured rows include `line_breaks`; mismatches report
`row_count_mismatch` after retaining width, height, PAGE and byte diagnostics.
PAGE does not count as LINE, and unsupported rows omit the count. Profiles reject
duplicate object keys and case aliases of `required_line_breaks`. This checks
separator structure, not physical menu geometry or a generic selectable-row count.

The [literal](evidence/fit-prototype-literal-report.json) and
[wrapped](evidence/fit-prototype-wrapped-report.json) trials show the same wording
changing from414 units to280/120-unit lines, while a920-unit word still overflows.
Scale, position, unknown substitutions and source-control compatibility remain
outside this report's approval scope. `within_profile` means declared pen bounds,
not visual/gameplay acceptance or permission to patch. Strict patch planning and
copy validation are unchanged. Exact reproduction and authoring remain separate.

For a reviewed owned slot with the same literal encoding contract, use
`registry_author` to create a wording snapshot, then preview it with the existing
fit profile. The row's generated `encoded_sha256` can supply the reviewed
`stream_slot` recipe pin; English stays solely in the registry. Keep the source
preimage, slot extent and evidence explicit, then dry-run and apply to a new copy.
The [handoff check](evidence/authoring-flow-proof.json) verifies two wordings through
these existing owners. A wrapped preview or different source controls may need
a different patch contract; the strict planner still refuses incompatible bytes.

The same command accepts `profiles/fit/item-descriptions.json` with the live
`49ab69ac` ISO and canonical registry. Its78 selected descriptions reuse the
measurer with530-unit LINE-only boxes and each original JP two-/three-row limit.
All 78 are within declared bounds in the [current native-advance trial](evidence/fit-items-native-advance-report.json);
no extra code, handler or copied English was needed for this second consumer. The
[Job Center profile](profiles/fit/job-center-summaries.json) reuses the same
operation for 27 compact summaries: manual lines, no PAGE, 400 native units and
three rows. [Independent review](evidence/native-advance-exception-review.json) matches all
encoded bytes and widths; the widest line is 394 units. This does not check the
original streams, slot capacities, references or visual fit.

An entry's `numeric_bounds` also works with measured wrapping. Each bound applies
to one `0x7000` argument in stream order; the wrapper calls the existing numeric
measurer for each word atom. Conservative digit/sign widths determine breaks;
missing, unused, null or invalid bounds remain unsupported. Numbers stay intact,
so an overwide number still reports overflow. Nested strings remain unsupported.

The [native advance correction](evidence/native-advance-exception-proof.json)
reads the source-selected glyph that bypasses the renderer's usual advance floor.
Comma now measures 6 units; earlier reports used 20. All 108 selected entries pass
fresh checks, including the [village profile](evidence/fit-village-native-advance-report.json).
Both native source facts are required in each layout/font profile; missing or
mismatched facts refuse. Historical reports retain their earlier model's values.

## Standalone texture authoring

`--texture-profile` uses one codec for fixed-palette PS2 PSMT8 standard and
headerless TXDs, calibrated PSMT4 village plates (128×32/TBW2) and multipage
rasters (512×512/TBW8), and finite direct-color layouts. Source, selector and optional candidate PNG are pinned in a
separate profile; this operation publishes new standalone PNG/TXD files. Example
from this directory, after extracting the named source member:

```sh
unzip -p assets/cmb-members.zip 'GRAPHIC/EVENT.CMB/event/systex/win_w.txd' > /var/tmp/window.txd
/var/tmp/dokapon-go-tools --source /var/tmp/window.txd \
  --texture-profile profiles/textures/window-export.json
```

For discovery, use the same pinned source with a profile whose `operation` is
`"inventory"`, keeping `source_sha256`, `source_size` and `evidence` and omitting
`texture` and all PNG/render/pixel-policy fields. The report lists native names
and raw width, height, depth, raster format and version in source order; duplicate
names remain visible. A malformed raster header has a per-entry `metadata_error`.
Dictionary, native-envelope and name errors reject the entire report. Inventory
forbids `--apply` and `--output`; `codec_support: "not_evaluated"` means metadata
alone does not establish decoding or patch support. The shared
[index parser](texture_index.go) also supplies ordinary texture selection;
[verification and limits](evidence/texture-inventory-proof.json) cover the shared
parser and read-only report.

For authored asset tables, use `operation: "specification"` and a separate
`specifications` map keyed by stable asset IDs. Each value names an exact unique
`texture` plus optional `kind`, `description`, `jp_text`, `proposed_en`,
`difficulty`, `screen_hint`, `notes`, `archive` and `entry` strings. Omitted/null
annotations mean empty strings; archive/member and context are declared labels.
Missing/ambiguous names and repeated selection of one texture refuse. Output is
sorted by asset ID and retains the original native ordinal. Parsed headers stay
separate from actual decoded geometry and RGBA hashes; unavailable measurements
are null with diagnostics. The same codec handles decoding, including calibrated
direct-color inspection. This mode forbids apply/output and all authoring fields.
Duplicate JSON keys, field aliases and unpaired Unicode surrogates refuse.

Run the [small two-native example](examples/asset-specification/profile.json)
from the project root:

```sh
go -C tools/go run . --source examples/asset-specification/source.txd \
  --texture-profile examples/asset-specification/profile.json
```

At most 64 authored entries and 16,777,216 potential decoded pixels are selected
per source. These joins do not perform OCR, text discovery scoring, folder tiers,
flagging or archive-wide manifests. Use the separate manifest operation below
for those responsibilities.
See the [specification proof](evidence/asset-specification-proof.json).

For archive-wide discovery, use `operation: "manifest"` with an extracted CMB
source pin, `index_sha256`, an `archive` label and optional `specifications`.
Each authored ID joins an exact `entry` and `texture`; an empty texture selects a
raw PNG entry. Missing, repeated or ambiguous joins refuse the entire batch.
Every CMB entry remains in index order, including empty, non-texture and invalid
members. Native duplicates and unsupported rasters remain explicit error rows.
Actual dimensions and full pixel hashes stay separate from raw metadata.
Batch and specification decoding reuse one index for the unchanged source buffer;
standalone calls and new artifacts retain fresh parsing.
Raw PNG previews retain their original encoded bytes. Their RGBA hashes and
discovery use the historical Pillow 12.3 conversion, including its transparency
semantics; another PNG decoder can produce different 16-bit display pixels.

The manifest reports advisory glyph-tile counters, folder tiers and ordered flag
reasons from the historical scan. These identify review candidates, not text.
Images below 8 pixels or with dimensions not divisible by 8 keep null scores:
the reference fails in those domains. Decoded images still retain folder/name
hints. Undecoded images have no flag reasons.

Run the [mixed-entry example](examples/asset-manifest/profile.json) from the
project root:

```sh
go -C tools/go run . --source examples/asset-manifest/source.cmb \
  --texture-profile examples/asset-manifest/profile.json
```

Dry runs report the complete manifest and deterministic bundle hash. Add
`--apply --output /new/previews.zip` to publish one exclusive ZIP containing
`manifest.json` and its PNG previews. Preview names use numeric entry/native
ordinals, so source names cannot create path collisions or escape the ZIP.
Source/profile rechecks precede publication; existing paths are refused.

Archives stream up to 1 GiB. Bounds are 100,000 entries/raster rows, 64 MiB per
member decode, 1,048,576 pixels per raster, 268,435,456 potential attempted pixels
and 128 MiB for the ZIP. Exhausted pixel work remains a row error; entries are
never silently dropped. An oversized bundle refuses publication. Shared pair
comparisons and labelled contact sheets are described above. The original family
contract is now verified; see the final contact proof and the
[manifest proof](evidence/asset-manifest-proof.json).


With `operation` omitted, output is a JSON preview containing generated artifact/raster hashes.
Add `--apply --output /new/window.png` to export. To import, supply `png` and its
`png_sha256` in the same profile; relative PNG paths resolve beside the profile.
Optional `rectangles` are `[x,y,width,height]`; candidate differences outside their
union refuse. Omit rectangles for the full raster. Default import publishes a same-size
TXD using existing palette entries for indexed formats, preserving raw CLUT
bytes and original duplicate-color indices; monochrome font edits use direct pixels. Sources and existing outputs remain read-only.

The [8-bit round trip](evidence/texture-window-import-actual.json),
[4-bit round trip](evidence/psmt4-village-import-actual.json) and
[font-atlas round trip](evidence/font-atlas-import-actual.json) return identical
source TXD bytes after PNG export/import. Profiles select a
[window](profiles/textures/window-export.json),
[village plate](profiles/textures/village-plates-export.json) or
[font atlas](profiles/textures/font-atlas-export.json) through the same operation.
[Corpus parity](evidence/clut-packet-proof.json) matches all 227 surveyed rasters:
150 PSMT8, 74 PSMT4 and three direct monochrome atlases. The existing packet checker
now handles the validated 128-square palette upload at Y=64; other positions
remain unsupported. The [metadata correction](evidence/texture-metadata-proof.json)
checks separate raster-format/version and palette-base/TEX1LOW fields; old
combined-field labels in historical receipts are superseded. Font export displays PS2 alpha as `min(255,2*raw)`;
changed font pixels store `(candidate_alpha+1)/2`, rounded down after division,
with half-step ties upward. Reports use `import_png` and hash the actual decoded
output, whose opacity may differ from an odd candidate alpha. Sources and
unchanged raw pixels remain intact. Default font mode refuses colored pixels; other layouts,
mipmaps and approximate palette replacement refuse. The [allocation validation](evidence/texture-footprint-proof.json)
checks native memory size in words against each calibrated mode; malformed sizes
refuse before PNG/TXD output. This edits atlas pixels; glyph metrics,
neighbor suitability, visual acceptance and ISO application remain separate.

The [initial small PSMT8 proof](evidence/small-psmt8-proof.json) and
[grouped extension](evidence/grouped-psmt8-proof.json) calibrate these version2
partial-page layouts through the same index walk, CLUT conversion, quantizers
and publisher:

| Width | Supported heights |
|---|---|
| 16 | 16,32,64,128 |
| 32 or64 | 16,32,64,128,256 |
| 128 or256 | 16,32 |
| 512 | 32 |

One native page-allocation/base calculation handles the19 dimension pairs.
TBW2 layouts merge a palette upload at X48 into unused page space; wider layouts
upload the CLUT separately at position zero. The finite geometry set and native
TEX0 fields stay guarded. Sixteen new representative rasters have frozen
export/no-op/corner-edit/exact-palette outputs and actual CLI checks. Their source
members and unselected textures remain intact; this does not assert all1,089
discovery rows were individually authored. Existing fixture data covers11 new
tuples; three additional members cover the other five, using the same archive
and loader. Native upload/sample formats differ, so these mappings were joined
independently. Below16 crop/padding layouts remain unsupported.

The [multipage PSMT4 proof](evidence/multipage-psmt4-proof.json) adds the existing
512-square native mode to the same depth4 branch and address calculation. All
262,144 reference addresses and the old village mapping match; corner,
page-boundary and shared-byte edits preserve their exact expected TXDs. Six
internally consistent adjacent geometries still refuse. The extension adds
88 production bytes and no function, table, policy or writer. Both calibrated
PSMT4 modes retain their native allocation, packet and CLUT guards.

For a calibrated direct raster, `"pixel_policy": "rgba"` permits colored pixels
through the same codec. Omit it to retain the512-square version0 monochrome font
scope. Explicit RGBA accepts these native layouts:

| Native version | Dimensions | Storage |
|---|---|---|
| 0 | 512×512,256×512,512×256 | Headerless pixels |
| 2 | 256×256,128×16,16×16 | One upload header, no CLUT |

Export, no-op import and rectangle-bounded edits share the same pixel loop.
Raw source alpha above 128 still refuses, and hidden RGB at zero alpha is preserved.
The PNG alpha convention above is reversible over raw0–128; native GS blending
uses alpha/128 and is not simulated here. `pixel_policy` and `palette_policy`
cannot both be set. Other direct layouts remain unsupported. The initial
[RGBA proof](evidence/direct-rgba-proof.json) and
[five-layout extension](evidence/direct-layouts-proof.json) bind original source
members, independent whole-file/pixel oracles and actual standalone CLI checks.
Small rasters reserve complete native64×32 pages; their allocation is not simply
width times height. No new function, writer or runtime asset bundle was added.

For a whole standard PSMT8 import, `"palette_policy": "exact"` explicitly
regenerates the palette and indices. It supports at most 256 colors after PS2
alpha rounding and transparent-RGB normalization, using deterministic sorted
entries and zero-filled unused entries. Omit the field to retain the existing
palette. Exact policy requires a candidate PNG and refuses rectangles, export,
headerless formats, other depths and excess colors. It does not resize images.
The [verified exact-palette increment](evidence/exact-palette-proof.json) matches
five existing image fixtures byte for byte, preserves the 227-case default corpus,
and refuses the existing 1,513-color candidate. Its [native binding](analysis/exact-palette-native-binding.md)
keeps the calibrated upload/storage rules. Standalone conversion does not check
ISO/CMB palette aliases or approve artwork; placement retains its own review.

For images with more than 256 normalized colors, `"palette_policy": "quantize"`
uses the original weighted median-cut and eight-pass Lloyd algorithm. Smaller
images use the same exact branch. Both policies share normalization, histogram
and index generation in [generatePalette](texture_palette.go); the existing
codec retains native mapping and CLUT writes. Quantize requires the same whole
standard PSMT8 input and refuses rectangles, export and other formats.
The [verified increment](evidence/approximate-palette-proof.json) matches seven
independent whole-file, CLUT, pixel and RGBA oracles, including the actual
1,513-color Goku image. Tests also cover numerical ties, empty clusters and the
material eighth pass. Floating parity is bounded to verified cases. This adds
5,593 production bytes and one shared function; it is capability growth.
The [full-page correction](evidence/fullpage-tbw2-proof.json) also verifies
128x64 and128x256 CLUT positions through the existing rule. It adds51 production
bytes, no function or policy, and reuses the source fixture. The [final independent assessment](analysis/texture-codec-final-assessment.md)
closes the original codec contract. Rendering, previews and placement remain
separate responsibilities. No ISO or visual approval follows.

The [shared bitmap renderer](evidence/bitmap-render-proof.json) uses the same
`--texture-profile` command with [HUD-label cells](profiles/textures/hud-labels.json).
Pass an extracted original `win_p.txd` as `--source`; preview reports the result,
and `--apply --output /new/labels.txd` publishes it. The profile pins a shared
[font descriptor](fonts/hud-labels.json) and atlas; cells hold text, colors and
rectangles. One compositor centers, outlines and shades the words, then feeds
the existing masked importer. All five cells reproduce the approved whole TXD
and raw RGBA. Colors are numeric arrays. Missing glyphs, overflow, overlapping
cells and invalid colors refuse before publication. The finite binary-font style
is verified; the bounded native run integration below adds antialiasing and
colored text. Other styles, TTF and donor reconstruction remain in progress. This adds12,694 bytes across code and runtime data, including
one justified function; test and fixture costs are separate.

The [native-font scaling foundation](evidence/raster-resize-proof.json) now has
one pure [resizer](raster_resize.go) for Gray glyphs and RGBA word layers. It
matches134 frozen pixel cases and8,803 independent filter coefficients, including
alpha rounding, source stride and per-pass clipping. The source, destination
and intermediate are each bounded to1Mpixels/4096 dimensions. The native-font
profile below now reuses this internal foundation through the existing command.
Its4,515 production bytes and1,457-byte required notice are charged together;
tests and fixtures are separate. See [Pillow's notice](licenses/Pillow.txt).

The [native optical run proof](evidence/native-text-proof.json) uses the same
command with [one original mini_g01 rule](profiles/textures/mini-g01-rule1.json).
Its shared [font descriptor](fonts/game-optical.json) holds glyph metrics and
atlas tiles; the recipe holds wording, colors, background and layout. Runs share
one quarter-step fit and native word renderer before the existing contained
import. Whole TXD, raw candidate and decoded RGBA match the canonical reference.
Active render profiles/font documents reject JSON null, unknown fields and visible
ink outside approved cells. The later four-style increment below extends this
initial small glyph-colored stroke scope; TTF and donor reconstruction remain
incomplete.
This increment adds36,712 runtime bytes, including font/recipe data and two
justified pure owners; tests16,566 and fixtures216,953 bytes are separate.

Standalone registry and texture outputs share [exclusive publication](outputs.go):
create a new file, sync, read back its bytes and verify the output inode. Failure
removes only the file created by that call. The streaming ISO patch writer keeps
its source replan, guarded edits and full-image verification.

## Shared operations

`patch.go` owns encoding, controls, planning, inspection and guarded copying.
`main.go` routes commands. [Registry document operations](registry_authoring.go)
own human/machine-field policy and source-derived reports; shared publication
stays in [outputs.go](outputs.go). Shared structs are grouped by usage:
[recipe/profile contracts](recipe_types.go), [text scanning](text_types.go),
[authoring fit](fit_types.go), [registry data](registry_types.go), and
[image/edit state](image_types.go).
They share the existing `main` package; another command would need an importable
shared package. Recipes do not require script-specific handlers. `{{PARAM:0x9000}}` and `{{ICON:0x9000}}` use the same
self-contained source token grammar. Opaque payloads cannot use these aliases;
measured variable layout still refuses until its semantics are bounded. See the
[shared grammar checkpoint](evidence/icon-grammar-checkpoint.json).

`source_context: true` opts a `stream_append` table into source-aware encoding;
it requires measured `layout` and forbids independent `prefix_words`. The shared
encoder retains source header/speaker context, checks positional marker order,
and appends the source's final PAGE pause even when English already ends in `//`.
It trims line-edge whitespace. Optional positive `layout.columns` and `layout.rows`
apply the reference character-budget wrapping policy; each selected row then needs
`encoded_sha256` and `max_new_bytes`. These authoring budgets do not prove physical
fit. Existing recipes keep literal encoding unless they opt in.

An individual row can select `authoring: "ordered"` to bind every original
control occurrence, including body setup/pen words and eight-byte opaque arguments.
The same policy is available as audit `canonical.authoring` and fit `authoring`.
English still comes from the selected registry ID. Its markers consume source
occurrences in order, including distinct payloads on repeated control codes:

| Marker | Source contract |
| --- | --- |
| `{{PARAM:0xb000}}` or `{{ICON:0xb000}}` | Copy the next actual argument, including its full payload. Spelling does not choose argument width. |
| `{{STATE:0x4001}}` | Place the next setup/true-pen word. Scale-like `e800..efff` is excluded. |
| `{{HL:0xb001}}` | Declare an explicit highlight-pair occurrence, including one originally before the first glyph. |
| `{{INIT:0xb007}}` | Declare persistent source-prefix colour/scale state before any emitted content. Its role is authored, never guessed from an odd highlight count. |
| `[spk 0x3802]` | Place the next actual body speaker after its source LINE/PAGE boundary. A leading speaker override replaces an existing prefix speaker in place. |

Headers and prefix speakers retain their original positions among the explicit
occurrences. Duplicate prefix speakers, missing, reordered, invented or wrong-role
controls refuse. Fixed
prefix anchors must complete before glyphs, spaces or line/page breaks. Opaque
payload bytes never enter wrapping or highlight scans. Character budgets estimate
arguments as one character and formatting as zero; setup/true-pen streams require
explicit breaks. Ordered native wrapping remains unsupported. Exact whole-stream
no-ops retain original synonymous glyph codes; changed wording uses the canonical
glyph map. Plain authoring also retains source-prefix scale words in order,
without claiming native scale semantics.

Ordered patch rows require a complete `expected_hex`, `encoded_sha256` and
`max_new_bytes`, in addition to the existing source-context append/layout guards.
Successful serialization does not bypass native measurements, references, byte
bounds or the strict edit validator. Unknown opaque/position-dependent patch
applications still refuse. The [contract](analysis/ordered-text-contract.json)
and [independent literals](testdata/source-ordered.json) describe this boundary.

A row's `numeric_bounds` declares `{"min": 1, "max": 10}` ranges in `0x7000`
argument order. The native width validator consumes every declared range, uses
conservative digit advances and rejects null entries, unused bounds and values
outside the nine-digit formatter domain. An empty object means the normal Go
zero-value range `0..0`; recipes must declare the actual caller domain. Other
number formats, nested strings and setup/position widths still refuse.

The [formatted-event pilot](recipes/initialized/native14/formatted-events.json) selects one
trap-count entry on its exact source14 image, with an encoding pin, byte cap and
reviewed `max_width`/`max_lines`. Select this file alone for its one-entry plan,
or `recipes/initialized/native14` for the combined 173-entry plan. The existing
planner shares one allocator across compatible tables; each table retains its own
pointer/landing scopes, encoding policy and geometry checks. Tables must have the
same source, mapping and native profile. Directory filename order, then numeric
registry-ID order, determines allocation; reversing tables can change addresses.

The [single-entry checkpoint](evidence/formatted-events-checkpoint.json) and
[composition checkpoint](evidence/append-composition-checkpoint.json) preserve
separate application identities. Menu recipes pin a different staged image and
remain outside this cohort. Selecting only `event-streams.json` retains the old
172-entry output and its reviewed Menu chain. Neither proof establishes complete
family coverage, gameplay or shipping readiness. Earlier literal source-context proofs
remain in their [own checkpoint](evidence/source-context-checkpoint.json).


| Operation | Purpose | Tables |
| --- | --- | --- |
| `registry_author` | Guarded existing-ID English/note edits | [verified request](evidence/registry-authoring-demo-input.json) |
| `registry_add` | Reviewed new draft rows, content collisions and exact all-present no-ops | [precode lifecycle vectors](testdata/registry-add.json) |
| `registry_reconcile` | Reviewed corrections and glossary proposals in one guarded ZIP of two snapshots | [paired fixtures](testdata/registry-paired.json), [example](examples/registry-reconcile/profile.json) |
| `registry_human` | Resolve authored text against decoded/flow scope, then refresh human fields with drift/status guards | [human fixtures](testdata/registry-human.json), [example](examples/registry-human/profile.json) |
| `registry_export` | Ordered scalar CSV projection with numeric ID ordering and an exclusive new output | [canonical columns](recipes/reports/registry-export.json) |
| `registry_status` | Pinned registry, glossary and flow facts rendered through one reviewed Markdown template | [inputs](recipes/reports/registry-status.json), [template](recipes/reports/registry-status.md.tmpl) |
| `registry_merge` | Guarded machine-field snapshot updates | [controller](recipes/registry/controller.json), [GP references](recipes/registry/gp.json) |
| `registry_markup` | Derive source markup metadata into a new snapshot | [markup](recipes/registry/markup.json) |
| `text_shapes` | Read-only shape and cluster summaries from one decode | [combined reports](recipes/reports/text-shapes.json) |
| `reference_observed` | Strict words and targets at every declared site in one registry family; preserves divergent targets and mapping failures | [family selector](recipes/reports/observed-references.json) |
| `reference_candidates` | Read-only reference candidates, collisions and query summaries | [discovery queries](recipes/reports/references) |
| `elf_layout` | Read-only LOAD headers and file-backed/BSS/unmapped address ranges | [frozen executable queries](recipes/reports/elf-layout.json) |
| `same_length_stream` | Equal-length text with ordered controls | [inplace](recipes/inplace.json) |
| `stream_slot` | Terminated text within a fully guarded slot; zero tail and pinned active encoding | [verified prototype](evidence/stream-slot-proof.json) |
| `fixed_field` | Plain glyphs padded to a fixed capacity | [rename fields](recipes/fixed-fields.json), [nicknames](recipes/nicknames.json) |
| `pointer_check` | Exact declared data/struct pointers and LUI/ADDIU words; apply refuses | [data selector](analysis/pointer-checks.json), [code selector](recipes/reports/code-references.json) |
| `stream_append` | Coupled payload/reference allocation in an initialized blob | [event streams](recipes/initialized/native14/event-streams.json), [menu labels](recipes/initialized/menu-labels.json) |
| `stream_grow` | Increase initialized disc/loader capacity while preserving content | [growth](recipes/capacity/initialized-growth.json) |
| `stream_allocate` | Reserve pristine disc space and zero reclaimed bytes | [allocation](recipes/bootstrap/allocation.json) |
| `guarded_words` | Documented word templates with named bitfield fixups | [loader](recipes/code/loader-code.json), [consumers](recipes/bootstrap/consumer-stage/consumer-install.json), [spacing](recipes/layout/space-width.json) |
| `cmb_member_replace` | Fixed-size named CMB members from a pinned ZIP bundle | [142 TXD members](recipes/assets/cmb-members.json) |
| `iso_file_replace` | Equal-size named ISO files from a pinned ZIP bundle | [current executable](recipes/build/current/executable.json) |

`stream_slot` preserves the existing supported control sequence and absolute
positions of all controls except LINE, PAGE and END. Its complete preimage defines
the slot; the encoding hash binds the active stream before zero padding. Existing
strict stream/plain-field operations keep their own contracts. The
[prototype proof](evidence/stream-slot-proof.json) verifies forward/reverse mixed
word/text copies on synthetic sources. A separately reviewed [native label
trial](evidence/native-slot-proof.json) translates one original slot, and the
[canonical Japanese restoration](evidence/jp-selector-proof.json) reproduces every
byte of the original ISO in a new isolated copy. Native ownership remains specific
to the reviewed slot; these are not visual or whole-game authoring claims.

Slot tables default to registry `en`. Setting `wording_field` to `jp` selects the
same entry's canonical original wording for restoration; it requires a nonempty
JSON string and a matching active-encoding hash. Other selectors or operations
refuse. [Forward](recipes/text/native-slots/defense-label.json) and
[restore](recipes/text/native-slots/defense-label-restore.json) recipes contain
source/target pins and preimages, without copying runtime wording. Apply still
uses the existing exclusive writer and all source, control and output guards.

Text keys are registry IDs. Machine-word keys are addresses under the table's
explicit mapping. One-level `word_blocks` share templates; fixups fill named zero
fields. Unknown controls, unused blocks/values, overlapping edits, incompatible
pins and mixed text/word profiles refuse.

Named bundle operations take one recipe and a source ISO without a registry
or glyph map. `cmb_member_replace` resolves indexed archive members;
`iso_file_replace` resolves whole ISO files after any separate allocation stage.
Both check exact extents, source and replacement hashes, and equal lengths.
`bundle_path` is relative to the recipe file. Dry runs report
member offsets, lengths and hashes without dumping texture bytes. Apply uses the
same exclusive copy, complete-source replan and readback as text edits. The
[scratch-stage proof](evidence/cmb-members-stage-proof.json) establishes byte
equality with the shipping reference for these members, not visual correctness.
`output_sha256` is an enforced whole-output digest, required for whole-file
replacement. `target_reference_sha256` names the reference image and is not
independently an output guarantee.

`reuse_table` is a small source-stage manifest for a reviewed `fixed_field`
or `cmb_member_replace` table. It names a relative `base_recipe`, pins its SHA-256, and
declares the new full source SHA-256, size and evidence. The loader copies the
base table's field facts into the existing planner only after the base hash
matches; the planner still checks every old field and the full staged source.
Bundle aliases also require an `output_sha256`; they preserve the base bundle
path and every member fact. The [current-build asset stage](recipes/build/current/assets.json)
therefore reuses the existing 142 rows without copying them.
The [rename/nickname manifests](recipes/stages/fixed-fields-current) reuse the
original 160 rows without copying them. Their [dry run](evidence/fixed-fields-current-dry-run.json)
and [isolated scratch proof](evidence/fixed-fields-current-proof.json) match
the predicted full-image hash.

For a reviewed END-driven text consumer, `line_page_reflow` lets
`stream_append` change LINE/PAGE placement while preserving the ordered
non-layout controls and meaningful boundary signatures, including trailing
pauses. It requires the exact encoded SHA-256, byte ceiling, native-font width
and per-page line limits; changed boundaries and PAGE inside active highlight
refuse. The [40-row hint-NPC replay](evidence/hint-npcs-reflow-applied-recipe.json)
has a [shipping-equal byte proof](evidence/hint-npcs-reflow-proof.json), but is
[held after audit](analysis/hint40-boundary-contract-recheck.json): all 40 targets
omit a source trailing pause. Its recipe is retained as executed evidence and
excluded from active recipes. Six other rows remain held for PAGE inside HL.

## Canonical reference verification

`pointer_check` selects a complete `registry_patch_ref` family and compares every
declared site against its registry ID, or its canonical landing with
`pointer_state: "registry_landing"`. It supports pointer arrays, explicit struct
fields (`pointer_vma == struct_vma + field_offset`) and strict LUI/ADDIU pairs
using the same declared nonzero register. ADDIU uses signed low-half carry,
including 32-bit wrap. Mixed coordinates, duplicate/shared physical sites,
unsupported forms and word mismatches refuse. Sparse struct records need proven
coordinates before use.

The scope hash pins sorted `(LE32 expected word, LE32 site VMA)` pairs. Existing
data-only hashes retain their meaning; instruction scopes include complete
opcodes/registers and both sites. This pins selected physical words rather than
the entire registry document. The complete source image hash is checked too.
Instruction rows use the existing internal `guarded_words` format, as append
already does; the `pointer_check` table forbids apply, including composition.

The [code recipe](recipes/reports/code-references.json) selects three entries and
16 instruction words in one frozen extracted executable. It uses ELF-relative
source mapping (`iso_elf_offset: "0x0"`), unlike the older full-ISO data recipe.
The [proof](evidence/reference-check-proof.json) also checks a canonical-landing
pair and independent mixed data/struct/code fixtures. These are exact declared
word guards. They do not establish text payload equality, register liveness,
complete references, safe landing ownership or gameplay.

## Registry CSV export

`registry_export` previews the CSV row count, ordered columns and complete output
hash as JSON. Add `--apply --output /new/path.csv` to create the CSV through the
existing exclusive publisher. The registry remains read-only; existing outputs
refuse. Registry, glyphmap and update arguments are unnecessary and forbidden.

```sh
/var/tmp/dokapon-go-tools --source registry/string-registry.json \
  --recipes tools/go/recipes/reports/registry-export.json
```

The [recipe](recipes/reports/registry-export.json) pins one registry version and
keeps the historical fourteen-column order in `registry_columns`. Other views
can select 1..64 unique flat column names without changing Go code. Rows sort by
numeric hexadecimal ID while preserving ID spelling. Fields preserve Unicode,
quotes and embedded line endings; record terminators are CRLF. Missing/null,
false and integer zero become empty cells, matching the historical exporter;
true becomes `True` and integers retain arbitrary precision. Selected arrays,
objects and floats refuse. Unselected opaque metadata is ignored.

This exports the registry plan. Disc-truth ledgers, glossary/flow status reports
and rendering readiness remain separate. Refresh source pins deliberately when
selecting a different registry version; outputs are bounded to 64 MiB.

## Declared reference observations

After building the runner, select the [pinned family recipe](recipes/reports/observed-references.json)
and supply its matching extracted ELF and registry:

```sh
/var/tmp/dokapon-go-tools --source /path/to/extracted.elf \
  --registry registry/string-registry.json \
  --recipes tools/go/recipes/reports/observed-references.json
```

`reference_observed` selects the complete `registry_patch_ref` family. It reads
exact declared data pointers, struct fields or known-register LUI/ADDIU pairs;
it does not search for candidates or use a glyphmap. The source and complete
registry are pinned by hash. Every site retains its ordinal, raw words, mappings
and target or error. Repeated targets keep their individual sites; distinct
targets remain in source order and set `divergent`. Malformed instructions or
incomplete file-backed words leave the target null, with readable words retained.
There is no fallback to the registry ID or registered landing.

Existing `inspect` maps each complete four-byte site word, then one byte at each
observed target. A reconstructed target can be BSS or unmapped. A file-backed
target point does not prove a whole readable stream, a safe landing or runtime
reachability. `resolved` counts rows whose declared words were all interpreted;
it does not assert target agreement or gameplay. The JSON includes source,
registry and recipe hashes, and inputs are rechecked before output. Reports refuse
apply/output, composition, candidate-search fields and unrelated workflow inputs.

The strict input domain requires Unicode-scalar-valid UTF-8 JSON throughout the
registry, including opaque values. Unknown metadata is not rewritten; owned field
aliases and duplicate keys refuse. Existing candidate and registry-authoring
policies are unchanged. Profiles accept at most 1 MiB; sources/registry at most
64 MiB each, selected entries/sites at most 256, and compact report at most 64 MiB.
See the [proof](evidence/observed-reference-proof.json)
for frozen literal cases, native word facts and the earlier candidate byte check.

`normalizeReference` now shares coordinates among expected guards, append and
observations; `referenceTarget` shares observed word interpretation among append
and observations. Expected planning still does not read observed words. Append
retains its consumer ranges, target agreement and write authorization. It now
refuses unused struct coordinates on an array pointer, matching expected guards;
all 3,868 frozen canonical array entries already satisfy that shape.

## Paired stream comparison

Run the self-contained example from the project root:

```sh
go -C tools/go run . --stream-audit-profile examples/stream-audit/profile.json
```

The [profile](examples/stream-audit/profile.json) pins reference, observed and
UTF-8 glyphmap files by size and SHA-256. Paths resolve relative to the profile.
Registry ID keys select explicit half-open **file offsets**, with a declared
`narrative` or `positional` decoder for each pair. There is no style detection:
the same bytes can be valid in both grammars with different meanings.

The read-only JSON separates complete-window equality from bytes consumed
through END. It compares glyph words, mapped text, positioned controls, control
sequence, ordered argument words and opaque payloads separately. Payload contents
never become argument words or END markers. Control sequence ignores offsets;
positioned controls retain them. Shared decoder tokens retain their existing
`Kind`, `Word`, `Offset`, `Payload` JSON fields; payload bytes use standard base64.
A failed decode leaves semantic comparisons `null`, with raw window hashes and
first byte difference still available. Tails remain visible even when consumed
streams match. Inputs are fully hashed and rechecked before publication.

The profile is limited to 1 MiB and 1..4096 IDs; glyphmap to 4 MiB, each even
window and expanded glyph text to 64 KiB, serialized report to 64 MiB. Source
files in the plain profile use bounded windows and streaming hashes, rather than
whole-file buffering. All other workflow flags, including apply/output, refuse.
Without the optional binding below, input IDs are attribution; this does not
resolve live references, construct canonical English, expand runtime
arguments, measure fit or prove gameplay. The [proof](evidence/stream-audit-proof.json)
binds independent literal cases, refusals and the public example.

### Binding observed windows to declared sites

Run the second example from the project root:

```sh
go -C tools/go run . --stream-audit-profile examples/reference-bound-audit/profile.json
```

Its [profile](examples/reference-bound-audit/profile.json) adds `observed_family`
and a fourth pinned source, `registry`. Existing `references` reads that family's
declared sites from the observed ELF. Family IDs and pair IDs must match
numerically; every declared site must be readable, valid and point to the same
target. Existing `inspect` then maps the **entire observed window**, including
post-END tails, from that target to exactly the declared file range. Divergence,
failed sites, BSS, unmapped bytes and split mappings refuse without partial JSON.
Reference windows and decoder styles stay explicit; no ID or target fallback.

The JSON adds `observed_references` and `observed_mappings`, preserving every site
and the complete-window mapping. Binding proves stored reference values, rather
than live readers, exhaustive references or canonical English. The example
deliberately includes content differences and a missing-END decode: valid binding
does not make unknown semantics equal. Inline fields declare `fixed16`: exact
eight-word decoding and complete original/observed field mappings replace
pointer interpretation. See the fixed-field example below.

Bound mode also buffers the observed ELF and registry, each capped at 64 MiB,
and inherits the reference reader's 256-entry/site limits. The reference source
can still be streamed. Registry hash, identity and modification time are rechecked
with the existing source lifecycle before output. Plain profiles keep their
three-input behavior. All five example inputs count as runtime data; see the
[proof](evidence/reference-bound-audit-proof.json) for checks and limits.

### Comparing canonical wording with installed streams

```sh
go -C tools/go run . --stream-audit-profile examples/canonical-audit/profile.json
```

The [self-contained profile](examples/canonical-audit/profile.json) keeps the
same pinned inputs and strict observed-site binding. Each selected narrative
entry can add `canonical: {"wrap": "none"}` or
`canonical: {"wrap": "characters", "columns": 2, "rows": 2}`. The latter
expresses a character authoring convention; it does not measure native box fit.
Explicit null policies or policy fields refuse; omission keeps ordinary audit
behavior. No-wrap rejects character budgets. Character columns and rows must each be
within 1..4096. Canonical policies require `observed_family`; positional labels
and native-width wrapping retain their separate existing contracts.

`auditStreams` takes English only from the pinned registry's normalized ID and
uses the separately pinned reference window as original context. Existing
`controls` and `encode` preserve the original prologue, speaker, arguments and
final pause. There are no supplied expected bytes, prefix retries, hidden default
budgets or text normalization to turn a mismatch into success. Missing wording,
missing glyphs and unsupported source context leave `canonical.error` visible
and `canonical_comparison` absent. Original/observed facts remain available.

A successful generated `canonical` side uses the same token/hash structure;
its `span` is a zero-based generated-buffer range. `canonical_comparison`
compares its through-END stream with the independently bound observed stream,
using the existing glyph/control/argument/payload factors. The original
`status` and `comparison` still describe reference versus observed. Therefore
`status: compared` alone is not a canonical match, and equality to Japanese
bytes alone is not evidence that text is untranslated. Observed post-END tails
remain separate. Registry EN and generated bytes are each capped at 64 KiB;
all existing pin, identity, bounded-report and no-write checks still apply.

The eleven frozen literal cases include control-only and argument differences,
unknown opaque contexts, source setup, missing END, explicit character wrapping, tails,
and relocated wording that correctly matches both original and canonical text.
They establish this finite narrative contract, not whole-ledger or gameplay parity.

Source-context encoding also preserves a decoded, payload-free leading setup or
non-scale pen prefix in source order, with at most one header and speaker. The
speaker override stays at its original ordinal. These prefixes use the existing
source decoder for validation, while translated content keeps the strict generated
grammar. Prefix words do not consume the character budget. Headerless setup is
supported; the independently captured `0x458f20` source with synthetic A wording
encodes as `01404500001000f8` using the frozen original glyphs.

State prefixes are limited to 4096 words. Colour/icon combinations, scaling words,
opaque payloads and setup/pen words inside content retain their separate refusal
policies. In particular, an old encoder dropped eight opaque payload bytes; that
success is deliberately not reproduced. The existing literal, positional and
ExactControls validation paths keep their contracts. Native geometry and complete
append/write validators remain separate: a generated expected stream is not patch
authority or evidence that those new prefix forms are safe for a native reader.

## Registry progress report

`registry_status` uses the same preview/apply interface and exclusive publisher.
Its [recipe](recipes/reports/registry-status.json) pins the source registry plus
three `registry_inputs`: glossary, milestone flow and the Markdown template.
Supplemental paths resolve relative to the recipe. `updated` supplies the report
date; `registry_columns` orders groups and must include status, source_pool,
chapter and tier. Additional nullable string groups need only recipe changes.

The JSON receipt contains all counts and source-order empty-English/missing-tag
IDs. Flow VMAs count exact nonempty spellings, without address normalization.
Missing status/provenance becomes `unknown`; explicit null stays distinct.
Other groups combine null/missing into `unknown`. Empty strings remain visible.
Glossary entries/todos default to empty only when absent; schema accepts JSON
scalars, preserving null separately from absence. Selected nontext group values
and malformed documents refuse before publication.

One [plain template](recipes/reports/registry-status.md.tmpl) owns prose and layout;
Go owns facts and Markdown-safe category labels. Unknown provenance is visible.
The date, escaping and presentation deliberately differ from the old Markdown;
the [verification](evidence/registry-status-proof.json) compares every meaningful
fact independently. These are plan facts, without installed-content verification.
The pinned template is trusted recipe data, limited to 1 MiB. A post-render
64 MiB output check is not a CPU or memory sandbox for arbitrary templates.

## Registry machine updates

A `registry_merge` recipe uses `--source` for a registry snapshot and `--recipes`
for one update table. Omit `--registry` and `--glyphmap`. It requires the exact
`source_sha256`, `source_size`, an `evidence` reference, an explicit `updated` date
(`YYYY-MM-DD`), and `registry_updates` keyed by hexadecimal registry ID:

```json
"registry_updates": {
  "0x536370": {"status": "patched", "patch_ref": "reviewed-proof-reference"}
}
```

The default previews the declared updates and predicted output hash. Adding
`--apply --output /new/snapshot.json` writes and reads back an exclusive new file.
Duplicate/missing IDs, human-field changes and backward/invalid statuses refuse.
Root and entry object keys with unpaired Unicode surrogate escapes refuse; nested
raw keys/values remain opaque. Valid surrogate pairs and U+FFFD keys are preserved.
Unknown fields and exact JSON numbers survive; top-level and entry keys are sorted,
and JSON formatting is normalized. Nested raw objects retain their original key order. Sources over 64 MiB refuse. Every rewritten registry snapshot also passes a
conservative two-space formatting budget and stays within that same ceiling;
all-present draft additions still return exact original bytes. The [checks](evidence/registry-core-checks.json)
and [independent review](analysis/registry-core-contracts.json) use synthetic data;
no canonical registry has been modified.

The verified [controller](recipes/registry/controller.json) and [GP-reference](recipes/registry/gp.json)
tables replace four-ID status/provenance bookkeeping and nine-ID reference backfills.
Select one file, using the exact pinned snapshot as `--source`; the directory is
not a combined transaction. Their Python mutation routes are reference-only.
Full-policy reviews, regression and exclusive-copy proofs are recorded in
[the migration record](MIGRATION.md). These do not replace `registry_io`'s 85 import
callers. The native `registry_markup` operation below now supports derived markup
metadata; its Python mutation routes are now reference-only. The two dated report imports
have reviewed historical dispositions, as does the completed Yes/No human correction.
Both independent reviews and the full regression are recorded in its closure. Their mutation
interfaces are withdrawn, and frozen original facts remain available as evidence.

## Registry draft additions

`registry_add` uses the same registry source, six-field table and exclusive-copy
workflow as `registry_author`. Each `registry_updates` key supplies the new ID;
omit an inner `id`. A minimal row is:

```json
{"jp":"名前","en":"Name","status":"drafted","source_pool":"unknown"}
```

`jp`, `en`, `status` and `source_pool` must be strings. English may intentionally
be empty and the source pool must be nonempty. New rows must start as `drafted`;
existing matching rows ignore incoming status after the string check. Other metadata
stays raw. New IDs use lowercase `0x` spelling; existing IDs keep their spelling.
A batch with additions sorts the complete registry numerically and stamps the
explicit `updated` date. Reports distinguish `added_ids` from `already_present_ids`.
An existing ID with identical JP/EN keeps **all** existing metadata and status,
even if incoming metadata differs; changed JP/EN refuses. An all-present batch
returns the exact original bytes, hash and date. Apply can still create a new,
exclusive copy of those bytes.

This operation accepts reviewed draft data. It does not validate glyphs, speaker
or marker parity, native fit, reference topology or patch readiness. Use the
existing text tools for those contracts; historical batch policies remain in the
[source study](analysis/registry-insert-contract.json). The
[verification record](evidence/registry-add-proof.json) covers the lifecycle and
preservation checks.

## Pinned draft batch imports

`registry_add` can replace `registry_updates` with one `registry_import`
declaration plus `registry_inputs`. Each named input supplies `path`, `size` and
`sha256`; paths resolve beside the recipe. The same admission and merge path
handles ordered JSON or CSV batches. Preview the synthetic example from this
folder:

```sh
go run . --source examples/registry-import/source.json \
  --recipes examples/registry-import/profile.json
```

Add `--apply --output /new/draft-snapshot.json` to create an exclusive new copy.
The canonical registry and all inputs remain unchanged. An import declaration is:

```json
{"policy":"json_kinds","batches":["batch"],"glyphmap":"glyphs"}
```

Use exactly its batch resources and one distinct glyphmap object. The `full_sweep`
preset also declares a distinct `marker_orders` resource. Limits are
1..64 unique batches, 65,536 total records, 64 MiB combined batch bytes and
64 MiB for the glyphmap. Every batch is valid UTF-8. JSON batches are bare arrays;
CSV requires the original ten headers, unique names and fixed row widths.
Quoted commas, quotes and CRLF metadata are preserved. CSV provenance is bounded
before copying it into every row; these ingress limits are not an output or memory
sandbox. All rewritten registry snapshots also fit the 64 MiB source ceiling. The complete compact
merged document passes a conservative two-space indentation budget before pretty
printing. Empty containers can make that estimate exceed the actual formatted
size, so a request near the ceiling may refuse below 64 MiB. All-present batches
still preserve exact source bytes without reformatting. IDs normalize before
cross-batch duplicate checks; unknown JSON metadata and numeric lexemes survive.

| Policy | Required input and lexical comparison |
|---|---|
| `json_kinds` | Ten truthy fields: `id jp en chapter character tier status source_pool ref_type discovered_by`. Compare ordered fixed-four-digit HL/PARAM kinds. |
| `json_codes` | The first eight fields above. Compare case-sensitive code-string multisets, accepting variable hex width and ignoring marker kind/order. |
| `full_sweep` | The ten fields and apostrophe gate of `json_kinds`; explicit pinned occurrence mappings can authorize a reviewed marker permutation. |
| `converted_markers` | Draft row fields `id jp en status source_pool`. Convert fixed-four-digit `<<HL/PARAM:0xNNNN>>`, lowercase codes and derive ordered `standalone_codes`/`param_blocks`; compare that metadata and marker kinds. |
| `csv_drafts` | Headers `id jp en chapter character event tier mode source_pool note`; add a 1..512 UTF-8 byte `discovered_by` label to the declaration. Project original draft defaults, null empty events, omitted empty modes and provenance notes. |

All five policies check page counts and matching page-leading speaker tags.
They remove their recognized markup before glyph-membership checks; spaces are
ignored. JSON policies also ignore raw `<0x...>` echoes. Only `json_codes` permits
curly or backtick apostrophes when present in the glyphmap. No Unicode
normalization is applied. Malformed closed speaker tags refuse; body tags retain
the historical lexical policy. Note wording never waives a marker mismatch.

These are deliberately distinct **draft admission** policies. Kind-only checks
can admit changed code values. Code multisets can admit changed marker kinds or
order. Converted metadata describes angle markers only, not existing curly
markers or opaque payload widths. None proves source-control identity, native
fit, references or patch readiness. Use the existing byte-aware text tools for
those checks. Per-pool construction and note facts use the existing insertion and
field owners described below. Current pool resources already contain their
reviewed ownership choices; source payloads still require byte-aware evidence.
The [independent fixtures](testdata/registry-import.json)
keep weak historical admissions separate from refusals and strict wire rules.

## Reviewed full-sweep marker orders

`full_sweep` retains the ten-field, straight-apostrophe and default marker-kind
sequence checks. It adds one named resource to the existing import declaration:

```json
{"policy":"full_sweep","batches":["drafts"],"glyphmap":"glyphs","marker_orders":"orders"}
```

The recipe still has seven root fields. The `orders` input uses the same
path/size/SHA256 pin as other inputs. An empty `{}` means ordinary kind-order
checks apply throughout. A supplied record is keyed by numeric registry ID:

```json
{"0x1000":{"jp_sha256":"<decoded JP UTF-8 digest>","en_sha256":"<decoded EN UTF-8 digest>","en_sources_jp":[2,3,1]}}
```

English occurrence 1 takes Japanese occurrence 2, English 2 takes Japanese 3,
and English 3 takes Japanese 1. Positions start at one. The array must cover
both complete HL/PARAM tapes, use every Japanese position once, and preserve
each paired marker's kind and code. Both decoded text hashes must match. A
supplied mapping is checked even when ordinary kinds already agree; unused
records refuse. Distinct resource roles, normalized ID duplicates, unknown
fields and invalid Unicode also refuse. `marker_orders` belongs only to this
preset, including when its declaration would otherwise be empty.

Preview the small non-involutive example:

```sh
go run . --source examples/registry-full-sweep/registry.json \
  --recipes examples/registry-full-sweep/profile.json
```

The [five reward mappings](recipes/registry/reward-marker-orders.json) capture
reviewed lexical facts from the historical pool data. Repeated identical codes
are assigned by the declared segment roles. Their opaque payload identity and
reconstructed Japanese source frames still require byte-aware verification.
Without a supplied record, the historical kind-only gate can accept different
code values; that draft policy remains explicit. Free note text grants no bypass.

The mapping resource and full-sweep profile each cap at 1 MiB. A mapping has
1..65,536 integer positions; the resource is included in the shared 64 MiB batch
budget. All source/resource/profile bytes are rechecked before publication.
The [55 independent cases](testdata/registry-full-sweep.json) cover mappings,
ordinary checks, complete-row retention, conflicts and exact source no-ops.

## Historical constructor and note facts

The [historical discovery recipe](recipes/registry/historical-discoveries.json)
contains all 142 fixed constructor results as stable-ID data. It uses the existing
`registry_add` owner, rather than another generator. Preview it against the
version-pinned empty example registry:

```sh
go run . --source examples/registry-full-sweep/registry.json \
  --recipes recipes/registry/historical-discoveries.json
```

These rows preserve historical wording and reference facts. They are not current
canonical translations. Existing equal JP/EN preserves all existing metadata;
conflicting wording refuses the whole request. The source pin also prevents
applying this empty-registry recipe to another registry without explicit review.

The [five note examples](examples/registry-reward-notes/profile.json) express the
old warning headline as literal full-note values through `registry_author`.
Their [input snapshot](examples/registry-reward-notes/registry.json) is pinned.
This demonstrates the fixed data without a per-ID prepend function. Import
no-ops continue to preserve existing notes; separate field-owned updates remain
an explicit choice. The author operation retains its documented date behavior.

Current checked-in pool resources already contain the six reviewed pool2
keepers and omit their pool1 losers. Historical scratch inputs are unavailable;
no raw preselection replay or automatic winner selection is claimed. New
conflicting duplicates still refuse. The original generators and source
snapshots remain references for reviewed facts, not an operational dependency.

## Paired corrections and glossary proposals

`registry_reconcile` plans reviewed English corrections and glossary additions
from a pinned registry plus exactly three `registry_inputs`: `glossary`,
`corrections` and `glossary_proposals`. It shares the existing field owner,
serializer and verified exclusive publisher. Preview the synthetic example:

```sh
go run . --source examples/registry-reconcile/registry.json \
  --recipes examples/registry-reconcile/profile.json
```

Add `--apply --output /new/pair.zip` to write one ZIP with exactly `registry.json`
and `glossary.json`, in that order. Successful return verifies the complete
artifact. The pathname is visible during writing, so its appearance alone does
not indicate completion. This publishes snapshots, without installing either
canonical file. Extract the members to use them as inputs to later commands.

The recipe has exactly `operation`, `source_size`, `source_sha256`, `evidence`,
`updated` and `registry_inputs`. Named inputs use existing path/size/SHA256 pins;
paths resolve beside the recipe. Corrections are a bare JSON array of closed
objects:

```json
{"id":"0x10","old_en":"A","new_en":"B","note_suffix":" [reviewed correction]"}
```

All four values are strings; `id`, `new_en` and `note_suffix` are nonempty.
The authored suffix includes its own separator and historical wording. Matching
`new_en` is already applied and never appends again. Otherwise, a mismatched
`old_en` refuses the whole pair. Known locked rows are held while valid glossary
additions may advance. Only `drafted` and `zone_pending` permit an actual wording
change. Missing/null notes start empty on an append; other current note values
must be valid strings. Held and already-applied rows keep their metadata.
Registry IDs use the same numeric identity as existing operations; aliases
normalize before duplicate checks.

Glossary proposals are a bare array with exactly five nonempty string fields:
`jp`, `en`, `provenance`, `source`, `usage_note`. JP identity is exact, without
trimming or Unicode normalization. Duplicate existing/proposed JP keys refuse.
An existing identical JP/EN keeps all its provenance and metadata; a different
English rendering refuses the entire pair. New entries append in authored order.

Each unchanged member retains its exact bytes and date. Only a changed member is
formatted and stamped with `updated`. This deliberately improves replay behavior
from the old script, which rewrote both dates even when already applied. Existing
metadata and numeric lexemes remain raw. Preview and every refusal preserve all
inputs and create no output; an existing output path is never overwritten.

The profile caps at 1 MiB; each source/member caps at 64 MiB. Corrections and
proposals together cap at 64 MiB and 65,536 records; the existing glossary caps at
65,536 entries, as does the resulting glossary. The archive allows two bounded members plus 1 KiB of ZIP overhead.
The shared conservative indentation budget applies to changed members. These
limits are not a general hostile-memory sandbox.

The [52 captured terminology corrections](recipes/registry/terminology-corrections.json)
and [17 glossary proposals](recipes/registry/terminology-glossary.json) reuse this
operation as data. Their historical annotation suffixes are already authored.
The no-fix Doom row has identical old/new English and never appends a note. These
reviewed 2026-09-03 facts require new source pins and current-state checks before
use; their availability does not establish current applicability.

The [independent fixtures](testdata/registry-paired.json) cover paired states and
refusals. This first slice does not implement human drift/force rules or build
translations from decoded text/flow data. It proves no glyph, source-occurrence,
native-fit, reference or patch readiness.

## Human source and field ownership

`registry_human` joins pinned `decoded`, `flow` and `authored` inputs to create one
new registry snapshot. Its recipe uses the same six fields as reconciliation.
Preview the synthetic example:

```sh
go run . --source examples/registry-human/registry.json \
  --recipes examples/registry-human/profile.json
```

Add `--apply --output /new/registry.json` to publish through the existing exclusive
writer. Inputs and existing output paths are preserved. No canonical file is
installed. The [source resolver](registry_human.go) owns joins and precedence;
[the registry owner](registry_authoring.go) owns statuses, mutation and publication.

The authored resource has four explicit fields:

```json
{
  "translations": {
    "0x10": {"en":"A","chapter":"menu","character":"system","event":"label","tier":"B","note":"Reviewed wording."}
  },
  "jp_overrides": {},
  "overwrite_drift": false,
  "discovered_by": "reviewed human batch"
}
```

Each translation has exactly six nonempty strings. Chapters are `prologue`,
`opening`, `menu` or `character-nameplate`; tiers are `A`, `B` or `authored`.
Provenance is a nonempty string of at most 512 UTF-8 bytes, copied only to new
rows. The [62 captured historical entries](recipes/registry/human-authored.json)
keep these facts and the Girl JP override in a separate table. That table alone
is not evidence of current decoded text, wording readiness or installed bytes.

Decoded and flow resources are arrays of objects. IDs match numerically across
inputs; distinct spellings for one ID within an input refuse. Repeated identical
flow IDs collapse; repeated identical decoded IDs retain the last record. Only
the selected winner needs valid nonempty `decoded_jp`, unless an explicit JP
override supplies it. An override cannot replace a missing decoded row. Decoded
records without a VMA (missing, null or empty string) are ignored. Every flow VMA
must resolve, and its ID cohort must exactly match the authored cohort.

Existing rows always refresh the five metadata fields, including locked or
drifted rows. Locked JP/EN never changes. Other divergent JP/EN stays unchanged
unless `overwrite_drift` is true, and actual changes still require `drafted` or
`zone_pending`. Matching wording and metadata-only updates do not require a
known status. Missing/null/nonstring old wording counts as drift. Selected old
string fields require valid Unicode; unknown and machine fields stay raw.

New rows receive canonical numeric IDs, `drafted`, null landing/patch references
and `menu_labels` for menu chapters or `text_bank` otherwise. A semantic no-op
preserves exact bytes/date, even for escaped strings or unsorted rows. Real
changes sort the whole registry numerically and stamp `updated`.

Only selected rows receive human completeness checks. Unrelated incomplete
metadata is preserved; use `registry_status` for completeness reporting. This and
changed-only dates explicitly differ from the old script's global assertion and
unconditional rewrite. There is no glyph, fit, reference or patch-readiness claim.

The profile caps at 1 MiB. Registry and each input cap at 64 MiB; the three inputs
together cap at 64 MiB. Each source collection and the existing/result registry
cap at 65,536 records. Changed output shares the existing conservative 64 MiB
indentation budget. All source/resource/profile bytes are rechecked before output.

## Registry wording updates

`registry_author` reuses the guarded snapshot transaction for `en` and `note`.
Its recipe has exactly six root fields: `operation`, `source_size`,
`source_sha256`, `evidence`, `updated` and `registry_updates`. Use the same
`--source`, `--recipes`, preview and exclusive `--apply --output` workflow as
machine updates. Changed English requires `drafted` or `zone_pending` status;
unchanged English and notes may be submitted for locked entries. New English
must be nonempty. Values must be strings with valid Unicode; selected existing
English is checked before comparing it with a replacement. Duplicate keys at
rewritten object scopes refuse. Unknown fields and unrelated entries survive.

The [executed request](evidence/registry-authoring-demo-input.json) is synthetic
verification data, not proposed game wording. Its [proof](evidence/registry-author-proof.json)
checks a new 5,544-entry snapshot, exact field containment, source preservation,
existing-output refusal and reuse by the fit preview. The canonical registry
remains unchanged. This covers edits to existing IDs; discovery, new rows,
full historical imports and the 85 Python import callers remain separate.

## Derived markup metadata

A `registry_markup` table uses the image flags: `--source` is the original image,
`--registry` is the registry snapshot, and `--glyphmap` is the source glyph map.
The one reviewed table requires `source_sha256`, `source_size`, `scope_sha256`
(the registry bytes), `glyphmap_sha256`, `iso_elf_offset`, `elf_vma_delta`,
`evidence`, and an explicit `updated` date. Supplied `registry_updates` and image
patch payload/profile fields refuse.

The default previews internally derived updates. `--apply --output /new/registry.json`
creates a new registry snapshot through the same exclusive writer and readback;
the image, input registry and glyph map remain read-only. Only
`midcontent_markup_shape` is derived, for decoded drafted entries with one
non-struct reference and mid-content icon/pen0/param8 tokens. Existing unrelated
and human fields, unknown JSON and exact numbers survive. Zero selected entries
still refresh the explicit top-level date; historical per-tag dates are preserved.

Eligible English must be a string, null or absent. Invalid wording types refuse;
Python's coercion of false/zero/empty collections to empty wording is withdrawn
at this new input boundary. Undecodable or untargeted entries skip that check.
A null reference site refuses. Glyph lookup uses the reference decoder's canonical
decimal keys; unused aliases are ignored. Readiness describes markup structure;
it does not establish glyph coverage, layout, physical fit or gameplay.

[Full metadata replacement](evidence/markup-retirement-closure.json) records caller
retirement, the independent reviews, regression and exclusive-copy proof. Frozen
older proofs retain their own source and binary identities.

## Combined text-shape reports

`text_shapes` reuses the same pinned source, registry and glyph inputs, with
[one report recipe](recipes/reports/text-shapes.json):

```sh
/var/tmp/dokapon-go-tools \
  --source iso/original/original.iso \
  --registry registry/string-registry.json \
  --glyphmap extracted/glyphmap.json \
  --recipes tools/go/recipes/reports/text-shapes.json
```

The stdout JSON contains `shapes` and `clusters`, matching the two report summaries.
It includes clean rows and exclusion/decode-failure counts, highlight pairs,
source-order examples, detailed target rows, pen families and payload counts.
`--apply` refuses; capture stdout to a new scratch file when needed. The registry
uses an object with an `entries` array and unique hexadecimal IDs. Decoded entries
require string/null English and reference type. Historical helper APIs, list/map
registry variants, formatted stdout and default output-file writes are withdrawn.

[Native verification](evidence/text-shape-consumer-checkpoint.json) and the
[read-only actual report](evidence/text-shape-actual-report.json) are recorded.
The current snapshot excludes all three drafted rows as multi-site; separate
synthetic comparisons establish decoded-report behavior. The [two-report closure](evidence/text-shape-retirement-closure.json)
records caller retirement, two independent reviews and the terminal regression:
8,722 passed with the same 69 known failures. Eleven post-promotion checks pass.
[Final accounting](analysis/text-shape-retirement-final-accounting.json) shows
11,806 fewer runtime/data bytes across the same selected dependency population,
including native additions and ledger growth; this is not whole-workspace savings.

## ELF address mapping

`elf_layout` accepts a standalone, source-pinned ELF32 little-endian MIPS
executable and one recipe. It shares the existing read-only report lifecycle;
registry, glyphmap, composition, apply and output-file arguments refuse.

```sh
/var/tmp/dokapon-go-tools --source /path/to/SLPM_657.50 \
  --recipes tools/go/recipes/reports/elf-layout.json
```

The [example table](recipes/reports/elf-layout.json) pins the frozen executable
bundled in `assets/executable-49ab69ac.zip`. `address_ranges` maps stable IDs or
descriptive names to hexadecimal `start`/`end` pairs. Ranges are half-open; the
exclusive end may equal `0x100000000`. Omit the map for header inventory alone.
JSON reports preserve program-header order and split each query into
`file_backed`, `bss` and `unmapped` pieces. Only file-backed pieces have
`file_range`; `program_header` indexes the original header table.

LOAD payload bounds, memory bounds, alignment and overlap are checked. At most
4096 headers, 1024 queries and 65536 output pieces are accepted within a 64 MiB
source. Section-header errors from Go's ELF parser also refuse. A zero-sized LOAD
remains in the header table but maps no bytes. This report does not translate ISO
offsets, allocate storage or establish safe caves, runtime ownership or patch
readiness. Existing fixed-delta patch profiles retain their own contracts.

## Source stages and layout

1. Compose only `bootstrap/allocation.json` and `code/loader-code.json` against the
   pristine image. Their reviewed result reserves space and installs inactive code.
2. Apply `bootstrap/consumer-stage/` to that exact result. It activates the core
   loader/consumers and preserves six JP seeds. See [bootstrap proof](evidence/bootstrap-proof-status.json).
3. Apply `layout/space-width.json` to that core. The [default spacing proof](evidence/space-width-checkpoint.json)
   changes eight native instructions and yields the pinned SPACE14 source.
4. Select `initialized/event-streams.json` against that exact source. The [172-entry proof](evidence/native14-events-checkpoint.json)
   includes fresh reviews, a new copy, completed-state and private RAM checks. The
   [95-entry source24 proof](evidence/native-space-checkpoint.json) remains separate.
5. Apply `initialized/menu-labels.json` to the verified172 output. Its [two-label proof](evidence/menu-labels-checkpoint.json)
   covers Name and Girl.
6. Apply `initialized/menu-boy.json` to that result. Its [Boy proof](evidence/menu-boy-checkpoint.json)
   completes the three labels in the rebuilt branch. [Menu closure](evidence/menu-closure.json)
   covers all eight effects, guards and known callers under these prerequisites.
   Visual/gameplay verification remains open. The pristine164 example is a separate
   source profile, not a prerequisite already included in these bootstrap stages.

The historical spacing transition is separate: `layout/space-width.json` changes
all eight native SPACE instructions from 24 to 14 using the existing word operation.
Its [checks](evidence/space-width-checks.json) and [reviews](evidence/space-width-reviews.json)
and [scratch/RAM proof](evidence/space-width-checkpoint.json) cover the default
transition. Custom values and Japanese UI behavior remain open.
The explicit [restoration recipe](recipes/layout/space-width-restore.json) reverses
those eight assignments on that exact SPACE14 source. The [reverse proof](evidence/reverse-word-proof.json)
restores the full known SPACE24 predecessor through the same planner and copy
writer, after two fresh independent reviews. An optional `output_sha256` is
supported for word/slot transactions; every table must declare the same pin. Apply verifies the complete result and
removes its new output on mismatch. Preview reports the expected pin without
computing the target digest. This recipe cannot undo later mixed modifications.

The [172-entry transition](evidence/native14-events-checkpoint.json) now has its own source/data/copy proof.

An append row may be just `"0x498c90": {}`: JP and its optional header derive from
the pinned source. Canonical references, reviewed consumer/landing ranges, actual
blob contents and free capacity govern allocation. Partial pointers, unexpected
bytes, nonzero destinations and insufficient capacity refuse. Completed references
allocate nothing. Fixed readers additionally require bounded encoded bytes, read
padding and any reservation bookend.

Layout uses the actual source font and eight coherent native SPACE instructions.
Relative JP/EN bounds do not establish physical fit. Earlier analysis assumed
SPACE14 on a SPACE24 core; [the correction](evidence/native-space-correction.json)
retains historical byte/RAM proofs while withdrawing that width endorsement. The
77 entries are verified only through the separate actual14 source/text transition;
their source24 refusals remain valid.
Code-immediate support has synthetic coverage and an actual source-bound two-pair
Name proof. Each broader family still needs reference completeness, CFG/liveness
and geometry review. Exceptional width uses an exact encoding pin and byte cap;
variable END readers do not acquire an invented fixed read length.

## Evidence and ongoing review

[Current input accounting](analysis/go-current-input-accounting.json) measures
all Go implementation, runtime tables, fonts, notices and runnable data together;
tests and evidence are separate. The [historical formatted-events account](analysis/formatted-events-accounting.json)
retains its selected population and transitional Python references. Current Go
operations use Python as a behavioral reference only. Moving files, adding recipes
or keeping the same function count does not establish code reduction.

[Astra audits every two hours](.goal/astra-audits.json) are purely adversarial and read-only.
Astra challenges reuse, duplication, growth and unsupported claims; it has no
implementation or approval authority. Root evaluates findings and owns fixes.

The [four-style increment](evidence/native-styles-proof.json) enhances the same
rendering and texture owners, with no new function or dependency.
[An original tutorial recipe](profiles/textures/help00-turn-order.json) reproduces
the canonical whole artifact and6,411 native changes. Native layouts accept
`min_size`, `tracking`, ordered `strokes` (explicit glyph/color/outline roles), and
`composite` (`float` or default `pillow`). Scalar stroke retains its old bounds.
`background_rect` selects paint within the approved cell; ink may occupy the rest
of that cell without repainting its original background. Fitting is separate.
`palette_policy: "source"` projects edits onto colors used in the original selected
raster, then quantizes through the existing native palette. Raw mask checks happen
before projection. The source cache stores4,096 entries then searches uncached;
default quantization retains its existing4,096-candidate refusal. Source policy
requires indexed4/8 import with replacement and mask/render; export/direct32 refuse.
This adds11,091 runtime bytes (9,071Go+2,020profile); tests18,095 and fixtures
2,909,007 bytes are separate. Multiline groups, icons, TTF, donor reconstruction
and other styles remain gaps. Raster is Partial; no reduction or retirement claim.

The [shared multiline prototype](evidence/native-line-groups-proof.json) adds
optional `group` data to native cells: cell-relative `box`, `lines` of colored
runs, `leading` and `vertical_align` (`middle`/`top`). Shared layout supplies
style/size/minimum and `align` (`center`/`left`); omit its scalar `at`/`max_width`
for groups. Each group fits one size and rounds the destination after each line.
Fit geometry, approved writes and background paint remain distinct. Groups allow
1..16 lines within the existing raster and aggregate stroke-work bounds.
The [tutorial example](profiles/textures/help01-command-order.json) matches its
independent original whole TXD, decoded RGBA and11,735 native changes. Eight
frozen layout examples and focused tests/CLI/build/vet checks pass; the full
integrated/race suite is deferred. No functions added; runtime grows6,903B,
tests4,315B/fixtures280,722B separately. Icons, TTF and donors remain future
enhancements. Raster stays Partial; a usable toolkit does not require full
historical coverage.

Inline icons use the same fitted runs and approved-cell compositor. Put named
original-sheet rectangles in `render.icons`, then use an icon run instead of
text and colour:

```json
"icons": {"lr": [303, 290, 26, 13]},
"runs": [{"text": "Use ", "fill": [35, 25, 15, 255]},
         {"icon": "lr"},
         {"text": " now", "fill": [35, 25, 15, 255]}]
```

The icon map belongs to `render`; runs belong to a cell or group line. Icons
retain their original pixel size when text shrinks or scales horizontally.
`layout.icon_gap` defaults to two pixels on each side; explicit zero is valid.
Each line paints its text, then copies complete original RGBA pixels into its
icon slots before the next line paints. This preserves transparent hidden RGB
and ordered overlap. Both source crops and whole destination rectangles must
fit their declared bounds. Structured icon runs do not parse historical `{@...}`
markers. The [proof](evidence/inline-icons-proof.json) covers native optical fonts;
[TrueType authoring](evidence/truetype-raster-proof.json) now uses the same owners;
donor reconstruction remains open. No new function was added.

## Artifact snapshots

`--snapshot create|list|restore` manages opaque regular files without registry or
patch recipes. Preview is read-only; `--apply` creates new files. For example:

```sh
./dokapon-go --snapshot create --snapshot-dir /scratch/snapshots --tag before-edit --source /scratch/candidate.txd --commit <full-commit>
# Repeat create with --apply to reserve the tag and publish its verified files.
./dokapon-go --snapshot list --snapshot-dir /scratch/snapshots
./dokapon-go --snapshot restore --snapshot-dir /scratch/snapshots --tag before-edit --apply --output /scratch/restored.txd
```

A tag contains fixed `artifact.bin` and `receipt.json` names. The receipt is
published last and records size, digest, timestamp, caller-supplied revision and
optional `--note`. Tags are unique bounded ASCII names; existing outputs and
observed source/store/tag/receipt/payload symlinks refuse. Restoration verifies
the recorded digest before copying; listing reports `present-unverified` and
never calls a recorded digest freshly measured. Revision provenance does not
verify a checkout or restore a registry. Failed creates can leave an incomplete
reserved tag for manual inspection; there is no automatic deletion or repair.
Create/restore apply perform roughly three payload passes with bounded-memory
streaming. The [focused proof](evidence/snapshots-proof.json) covers31-byte and
2MiB sources, source preservation and corruption/publication refusals.
The [publisher](outputs.go) now shares streaming size/digest checks and readback
with registry and texture outputs; receipt reads reuse [readInput](inputs.go).
One justified lifecycle owner and no helper/dependency/closure were added.
Runtime grows11,070B/2files; tests5,519B separately. The snapshot checkpoint total was93files/731,386B; current totals are in the
[accounting report](analysis/go-current-input-accounting.json).
All14 core areas have scoped usable operations; the snapshot checkpoint full-family score was
4/14; the current assessment below promotes snapshots to Full. Snapshot history imports, workspace-wide auditing and hostile concurrent
namespace safety remain future/separate work. The earlier integrated checkpoint passes the full Go race suite below; later increments use focused checks.

The [integrated toolkit checkpoint](evidence/registry-owner-proof.json) passes the
complete uncached Go race suite, build, vet, formatting and scoped checks. Registry
policy now has one [document owner](registry_authoring.go); command routing drops
from737 to258 lines. Its existing482-line body is mechanically unchanged. This is
ownership cleanup with568B of source/import/type overhead, not code reduction.

For a new patch case, change an existing recipe/profile when behavior already
exists. For new behavior, start with the shared owner in the
[14-area map](analysis/reusability-coverage.md), update its contract and affected
callers, and add a focused behavioral check. Add a function only when those owners
cannot reasonably contain the responsibility. Keep read-only previews separate
from guarded publication; unsupported cases must refuse clearly.

The [snapshot family assessment](evidence/snapshot-family-proof.json) verifies the
unchanged explicit-version management contract, bringing full core coverage to
5/14 (35.71%). Create/index/hash/list/restore are shared operations with declarative
inputs; legacy ledger imports and workspace-wide reports are separate scope.
The [410-path responsibility refresh](evidence/toolkit-responsibility-audit.json)
provides routing to these owners while retaining historical and dynamic gaps;
its source classifications are not additional migrated scripts.


## Finite ordered reconstruction — 2026-10-21

The [proof](evidence/reconstruction-row-proof.json) and [independent review](evidence/reconstruction-row-review.json)
verify one shared flat/clear/row/column kernel inside the existing compositor,
native importer and publisher. Current donors/text and immutable icon sources
retain their distinct contracts. Mixed steps use explicit order and exact
allow/exclude/add geometry; native bounds are coarse guards. Canonical owned
JSON fields and caller-owned default-order storage have regression checks.

Production39files/417,383B/41declarations; runtime148files/2,375,964B,239inputs.
Growth13,759BGo/15,124Bruntime is capability growth, not deletion or relocation
savings. One function was justified before implementation; no new helper or
test function. Tests+21,101B/fixture350,493B are separate. All45source vectors,
shifted padded origins, whole native projection and focused native/core/race,
build/vet/format checks pass. Native expected bytes use the OLD accepted codec,
not an independent encoder. Full integration/gameplay remain deferred.
Raster5/6,planning65/84 andcore6/14 Full/410-path counts remain unchanged.
Other masks/morphology, PDE, exemplar, plate, radial/contour, material and
source-art algorithms remain; one primitive cannot close .06.


## Reusable color-exclusion masks — 2026-10-21

The [proof](evidence/reconstruction-mask-proof.json) and [independent review](evidence/reconstruction-mask-review.json)
verify RGB exclusions, finite ANDclauses with separate tolerances, andsat_lt
inside the existing reconstruction selector. RasterSelection groups the oldflat
fields; RasterErase.All adds at most32 clauses. The same kernel/nativewriter
handles currentpixels, growth, donors and write containment.0newfunctions/files.

Production39Go files419,307B/41declarations; runtime149files2,380,078B/241inputs.
Growth1,924BGo/4,114Bruntime includes the2,190B profile; tests+4,325B and
fixture155,124B separate. This is capability growth, with no savings, script
retirement or milestone credit.18neworiginalwholeRGBAoutputs/twoorigins plus
old45cases and exact5,685-byte native projection pass. Native expectation uses
the OLD accepted codec, not an independent encoder or artwork approval.
Focused native/core/race/build/vet/format andfreshreview pass; fullintegration
andgameplay remain deferred. Core6/14Full,planning65/84 andraster5/6 unchanged.
Broader shape/OR/morphology andvisual-source algorithms remain explicit gaps.


Source colour authoring: canonical audit policies may declare `"authoring":"plain"`
when leading colour is persistent source state. Omitted/`markers` retains the
existing ordered positional-marker contract. Plain rejects every `{{` substring,
including malformed markers, and refuses body colour, icons, opaque payloads and
scale controls. It copies source colour in original prefix order outside body
wrapping; source copy accepts decoded b001..b7ff without expanding authored
marker b001..b009. No fallback follows a failed marked encoding.
This read-only audit choice adds no planner/recipe/write authority. Native fit
and complete write validators remain separate. See
[reuse decision](analysis/source-colour-reuse-decision.json) and
[original policy frontier](analysis/source-colour-policy-frontier.json).


For inline names, [the fixed-field example](examples/fixed-audit/profile.json)
uses decoder `fixed16` and canonical policy `{"wrap":"none"}`. Each selected
registry row owns exactly one `struct_table_field` site with its ID as
`struct_vma`, offset0, stride0x10 and no pointer field. The existing observation
path reads four raw words; their target is null because glyphs are not pointers.
Both original and installed full16B fields must map to that declared location.
Every glyph word is checked, including words after zero padding. Zero is SPACE,
no END is accepted, and literal punctuation/spaces are preserved. Intentional
empty EN pads to16zero bytes; missing/null EN remains unknown. Unknown source or
observed glyphs remain visible with raw hashes; decoding success is not assumed.
Capacity, file boundaries and all original write/wording guards still apply.


The read-only sentinel audit example binds stored pointers to a complete external
text window: `go run . --stream-audit-profile examples/sentinel-audit/profile.json`.
The same allocation facts are available without text decoding through
`go run . --source examples/sentinel-audit/observed.elf --recipes examples/sentinel-audit/layout-profile.json`.
The example contains synthetic data, not game or runtime approval.


Read exact one-word argument/control dialects with
`go run . --stream-audit-profile examples/pinned-raw-audit/profile.json`.
Each side declares a full-span hash, word count, final relative-byte END offset
and reviewed raw roles. This example reuses original helper spans under synthetic
pointer ownership; it grants no canonical authoring or native execution claim.

GP-relative observed references reuse `ref_type: gp_relative` with existing
`addiu_vma` and `reg` site fields. The reader derives GP from one bounded ELF
register-info record, validates the instruction and reports ordinary target
mappings. This observes installed address construction; GP patching, runtime GP
and separate display ownership are not established. See `examples/gp-audit/`.

For discovery without a registry, index a declared file window:

```sh
go -C tools/go run . --source examples/gp-audit/observed.elf \
  --recipes examples/gp-audit/index-profile.json
```

`reference_gp_index` reports supported GP-base ADDIU, load/store, cache and
prefetch forms in source order. It reuses the ELF metadata and mapping reader.
Each instruction needs one complete aligned file-backed mapping; ambiguous
file aliases refuse. Optional `address_ranges` queries select computed byte
points, including unaligned points, rather than whole memory accesses.

The synthetic example contains three ADDIU instructions: one computes `0x100300`
and two compute `0x100700`. GP is an ELF metadata assumption throughout the scan;
prior instructions do not update it. Missing or invalid metadata retains rows
with null arithmetic, matches and target maps; zero GP remains known. ADDIU to
register zero is marked `discarded_value`. Memory forms report effective
addresses; `loaded_pointer_target` is always null. The numeric `rt` field has
opcode-dependent meaning. Mapping does not prove code, execution or ownership.

The read-only operation accepts one regular ELF up to 64 MiB, a nonempty aligned
window of at most 1,048,576 words, up to eight named queries and at most 32,768
supported rows. JSON output is buffered and bounded to 64 MiB. No registry,
glyphmap, recipe composition or write flags are accepted. The recipe and source
are rechecked before publication. See the [reuse decision](analysis/gp-index-reuse-decision.json)
for the source-derived contract and remaining analysis work.



### Local instruction facts

```sh
go -C tools/go run . --source examples/gp-audit/observed.elf \
  --recipes examples/gp-audit/instruction-profile.json
```

`instruction_index` uses the same source-word and ELF mapping checks as the GP
index. It retains every selected word, including unsupported forms. Finite
operand facts distinguish GPR destinations, other register banks, conditional
writes and merge dependencies. May/must destinations describe normal completion;
they do not prove a complete 128-bit overwrite.

Ordinary `ADDU` exposes its source reads, destination write and fallthrough.
Only zero-operand forms establish a pointer copy. Arithmetic involving a tracked
pointer still loses provenance; a destination-only overwrite kills its old alias.

Local control alternatives keep branch targets, likely-delay behavior and link
values separate. A link does not imply return. Missing, unsupported or control
words in a selected delay slot produce a delay error beside the raw alternatives.
Sequential next describes ordinary completion before predecessor delay context.
Scope checks use exact selected VMAs, including disjoint or reordered LOADs.

Profiles require operation, source size/hash, evidence and references.file_range.
The source is bounded to 64 MiB and the aligned window to 32,768 complete words.
Registry, glyphmap, address-range queries, composition and writes are rejected.
Without the optional register-flow request below, output remains the finite index.

### Querying register flow

```sh
go -C tools/go run . --source examples/gp-audit/observed.elf \
  --recipes examples/gp-audit/register-flow-profile.json
```

An instruction profile may add a top-level `register_flow` object containing
`entry_vmas` and a map of named `queries`. Entries assert normal execution at
selected words. Each query requires `kind` (`reaching_defs`, `uses_after` or
`reads_before_kill` or `pointer_consumers`),
`register` (0..31), `vma`, `context` and `max_visited_states` (1..100,000).
VMAs use the existing address-string syntax. Context is `normal`, `any_reachable`
or `delay`; only `delay` requires and accepts `delay_of`, the controlling transfer.

Definitions are searched before the queried word reads; uses are searched after
it executes. `reads_before_kill` instead includes the queried execution, checking
its incoming dependencies before a definite overwrite. Its work budget includes
the root and each distinct reached execution state. A physical word can execute
both normally and as a delay word.
Likely-branch annulment follows the selected outcome, and a link is visible
before its delay. The engine builds one graph per batch and preserves conditional
writes and merge dependencies instead of treating every destination as a kill.
Loops converge through visited execution states; they can revisit the query word.
GPR0 has no mutable definitions or uses.

Results separate sorted known sites, incoming entry sites and incomplete reasons.
An unknown exit or exhausted limit can coexist with useful facts. Forward sites
are dependency MAYREAD facts, including conditional preservation, not proof that
a pointed-to value is consumed. Empty sites prove no modeled read only when
`complete_within_asserted_scope` is true; an incomplete empty result is UNKNOWN. A reachable
unknown transfer holds backward completeness even when a known path reaches the
query, because the unknown target may add a predecessor inside the selected range.
Forward uses stop at a definite overwrite, so a later unknown exit need not hold
that earlier value. Completeness is
conditional on asserted entries, supported normal-completion effects and the
modeled low32 register value. It proves neither execution nor whole-program
closure; `whole_program_scope_proven` stays false. No call return, ABI clobber,
indirect destination, memory value or hook certification is synthesized.

Requests allow at most 256 distinct entries and 64 query labels (1..128 UTF-8
bytes each). Graph states are capped at 100,000 and aggregate admitted query
states at 1,000,000. Sorted query labels make shared-budget results deterministic.
The example finds the first ADDIU defining a1 before the third word; later GP
reads remain known while continuation outside the selected window stays held.

### Following pointer consumers

```sh
go -C tools/go run . --source examples/pointer-consumers/source.elf \
  --recipes examples/pointer-consumers/profile.json
```

A `pointer_consumers` register-flow query requires `seed_phase: "before"` or
`"after"`. The query label identifies an asserted incoming low32 pointer origin.
It follows copies, signed immediate offsets and aligned four-byte stack spills,
including aliases that survive overwriting the original register. Results separate
pointee reads/writes from pointer stores, call arguments, returns and provenance
loss. They retain delay context and literal memory displacement, not object bounds.

Calls stop after their actual delay instruction with an unknown continuation.
A false conditional link follows its existing fallthrough. Partial, merged, wide
or non-GPR spill reloads stay unknown, including possible overlaps after frame
precision is lost. Clearing a saved slot later cannot erase that uncertainty.
The analyzer uses the existing graph and charges repeated abstract-state work.

`stack_container_argument` observes a live four-byte pointer spill whose start is
within 64 bytes above an argument's exact stack-frame address. It reports the
minimum relative displacement after frame facts converge. Work, batch, spill or
graph limits suppress these observations; semantic uncertainty alone does not.
The window is a historical reporting convention, not an object size, callee read
or ABI proof. Direct-call policy declarations do not admit this event kind.

A reference-flow recipe can add `consumer_seeds`, keyed by a short origin name;
each seed supplies `vma`, `register`, `context`, `seed_phase` and optional
`delay_of`. It inherits the shared work limit. Shared `call_rules` map a target
to explicit `allowed_registers` (EE registers4..11) and `evidence`. An empty list
marks risk; a missing rule stays unknown. These are declarations bound to the
pinned source/profile, not proof of callee behavior. Risk outranks uncertainty;
a permitted call never erases its unmodeled continuation. Existing benign-reader
pairs do not waive pointer-consumer findings.

The [contract](analysis/pointer-consumer-contract.json) records limits and remaining
interprocedural/table/getter duties. This tool grants no patch or ABI authority.
The [retired static ELF design](analysis/retired-static-elf-design.json) is documented
separately; it is not a Go segment/BSS growth capability.

### Checking declared instruction readers

```sh
go -C tools/go run . --source examples/reference-flow/source.elf \
  --registry examples/reference-flow/registry.json \
  --glyphmap examples/reference-flow/glyphs.json \
  --recipes examples/reference-flow/profile.json
```

An existing `reference_candidates` profile may add `reference_flow` with explicit
`entry_vmas`, `max_visited_states` and an `entries` map keyed by selected registry
IDs. Each recipe may list exact `benign_reader_pairs` (`lui_vma`, `use_vma`,
`evidence`) and a bounded `zero_padding_allowance`. Owned lower sites come from
canonical registry sites. Entry flags and exclusions are not benign-use waivers.

The shared finite producer decodes the selected file range once; graph queries
cover registered lower/base pairs and every selected nonzero LUI, including
unregistered or unreachable candidates. Duplicate requests share one query.
More than 64 generated queries refuse before analysis. Existing graph, entry,
per-query and whole-batch bounds still apply. Mapping must agree with the
profile's flat delta. Source, registry, glyphmap and recipe identities are checked
again before the bounded report is published.
Recipe intake is limited to regular files up to 128 MiB before classification;
read-only report profiles retain their stricter 1 MiB limit. Known special files
are rejected before opening. This does not claim atomic protection against a
hostile path replacement between the metadata check and open.

The report retains old advisory rows and summaries. `instruction_index` contains
the authoritative decoded facts and generated `register_flow` queries. Requested
rows add `flow`, with query references, constructed targets, reader ownership,
ordered diagnostics and canonical-pair errors. Exact-pair collisions and lower-
instruction ownership remain distinct. A benign tuple for another LUI cannot
suppress a reader. All lower-site owners remain visible, including mixed statuses.

Definitions are checked before reads; reader queries start after each known
reaching LUI. Unknowns, incoming-entry values, non-LUI or multiple definitions,
unregistered high halves, mismatched targets and foreign readers remain refusals.
ADDIU uses signed lows modulo32; ORI uses zero-extended bitwise OR. Broader observed
arithmetic does not relax the strict LUI/ADDIU patch grammar. A discarded ORI
result still retains conservative explicit source-operand facts, as with ADDIU.

The default target is the stable ID. Explicit `pointer_state: registry_landing`
uses the canonical landing value, with no fallback for missing or malformed data;
zero-padding tolerance is forbidden in that mode. Original-ID padding tolerances
must fit the existing skip bound and every tolerated byte must be zero.

`eligible_under_declared_policy` means only these caller diagnostics passed under
the asserted entry/low32/normal-completion model. It grants no patch, target-backing,
consumer, ABI or whole-program authority. A noncanonical observation can retain
canonical-pair errors even when the listed caller rules pass. Real writes retain
the separate strict planner and byte guards.

### Reviewing registry bookkeeping

```sh
go -C tools/go run . --stream-audit-profile examples/reconciliation-audit/profile.json
```

The [profile](examples/reconciliation-audit/profile.json) uses the same four
pinned inputs and observed-family binding. An entry may add
`review: {"action": "allow", "reason": "Current pinned cohort reviewed"}` or
`action: "hold"`. Either requests reconciliation for the selected family;
entries without review remain held. Null review, unknown actions and blank
reasons refuse. With no review entries, existing audit output is unchanged.
Review records editorial scope for these inputs; it cannot supply byte proof.

Each row then adds `reconciliation`, retaining its independent comparisons.
Only a current `drafted` row with explicit allow, known exact
canonical bytes, zero observed tail and complete reference/window
binding can propose `status: patched` and `landing_vma`. Pointer streams use
the convergent observed target. Inline16 uses the field location proved in both
original and observed files; its glyph words never become pointer targets.
Inline proposal sites must omit `pointer_vma` entirely. Explicit empty/null keys
retain read facts but hold proposals, preserving the original source policy.
Unknown/missing/nonstring statuses, missing canonical evidence, mismatches,
tails and holds produce reasons without proposed fields. A matching `patched`
row reports `unchanged` with an attention
reason: no status promotion is needed, but landing metadata is not reconciled.
Other progressed statuses are preserved. Selected status aliases and duplicate
keys refuse; nested opaque metadata keeps its existing validation policy.

Proposals never contain EN, JP, note or patch_ref. In particular, decoded glyph
text is not a replacement for authored ICON/PARAM notation. The pinned registry
hash and stable ID identify the before-state; observed site words and complete
mappings identify the candidate landing or inline field. The
[fixed-field example](examples/fixed-audit/profile.json) includes explicit review
for a matching label, intentional empty wording, mismatch, hold, unknown status
and unavailable canonical generation. This is a read-only bookkeeping report,
not native fit, live/display ownership, patch authority or a new registry file.
A later publisher must independently recheck pins and existing field ownership.


### Installed stream line structure

An audit entry can add `"line_limit": 4` to request a `structure` projection.
The optional limit must be1..4096 and uses the declared narrative or positional
stream grammar. Fixed fields and pinned raw roles refuse this projection.
Without the field, existing report output is unchanged.

The report retains full reference/observed page arrays, including empty pages.
It trims trailing empty lines. Visible glyph, highlight, icon and opaque-argument
tokens each count once; zero SPACE/padding does not. Overflow indices refer to
nonempty pages and apply only to HDR streams. For headerless streams, an advisory
compares total nonempty-page line counts with the explicitly declared reference
window. An unreadable reference leaves that comparison null; it never falls back
to a registry address. These are token-line diagnostics, separate from font
advances, physical dialogue geometry and authored-text fit. They do not change
bookkeeping proposals or authorize a patch.

### Replaying the composed reports

The [frozen input bundle](evidence/joined-workflow-inputs.zip) contains synthetic
sources, explicit profiles and independent expected facts. From the repository
root, run the existing tools against a new temporary directory:

```sh
workflow_dir=$(mktemp -d /var/tmp/dokapon-report-demo-XXXXXXXX)
unzip -q tools/go/evidence/joined-workflow-inputs.zip -d "$workflow_dir"
go -C tools/go build -o "$workflow_dir/dokapon-tools" .
"$workflow_dir/dokapon-tools" --stream-audit-profile "$workflow_dir/inputs/audit-profile.json"
"$workflow_dir/dokapon-tools" --source "$workflow_dir/inputs/observed.elf" \
  --registry "$workflow_dir/inputs/registry.json" --glyphmap "$workflow_dir/inputs/glyphmap.json" \
  --fit-profile "$workflow_dir/inputs/fit-profile.json"
"$workflow_dir/dokapon-tools" --source "$workflow_dir/inputs/registry.json" \
  --recipes "$workflow_dir/inputs/csv-profile.json" --apply --output "$workflow_dir/registry.csv"
"$workflow_dir/dokapon-tools" --source "$workflow_dir/inputs/registry.json" \
  --recipes "$workflow_dir/inputs/status-profile.json" --apply --output "$workflow_dir/status.md"
```

To include structural facts, add `"line_limit": 4` to the selected entries in the
extracted audit profile. Compare source/registry/glyph hashes and selected IDs
before combining reports. Matching IDs alone cannot establish matching inputs;
matching input hashes cannot establish a complete selection. The example selects
10 of11registry rows and preserves an unreadable observed stream. CSV and status
counts describe the plan. Its authored-fit encodings differ from the canonical
streams because source headers are retained only in the latter; no installed-fit
conclusion follows from those fit results. The bundle's Python files are frozen
behavioral references, not required commands for this Go workflow.


Shared reconstruction permissions can be pinned once on `render.permissions` with
`path`, `size` and `sha256`, like other render resources. The path is relative to
the profile, and the JSON table is capped at1MiB. It contains `allow`, `exclude` and `allow_add` rectangle arrays, plus optional
`masks` in the same three stages. Local `reconstruction` retains erases
and `order`; inline permission arrays conflict even when empty. There is no merge,
override or recursive include. The existing combined64-region cap, three-stage
permission order, native-footprint intersection and text leak checks still apply.
Reports add `permissions_sha256` when a shared table is used.

The two help00 reconstruction profiles now share
[one permission table](profiles/permissions/help00-panels.json). The separate
[batch C panel facts](profiles/permissions/batch-c-panels.json) encode one fixed
source shape as13 rectangles, exactly matching all80254 original permitted pixels.
This is reusable data, not general rounded-rectangle or artwork migration support.


### Original-pixel permission footprints

A reconstruction can add `masks`, with `allow`, `exclude` and `allow_add` lists.
Each footprint requires `rect`, `any`, `fill` and `grow`. `rect` is XYWH and bounds
both sampling and topology. `any` is OR of AND groups of the existing selectors;
`[]` selects nothing and `[[]]` selects the complete crop. Original pixels supply
permissions before ordered text or erase steps change the canvas.

Selectors may add finite `above` and `below` maps. Properties are `luminance`,
`saturation`, `red`, `green`, `blue`, `alpha`, `red-blue`, `blue-red`, `red-green`
and `green-blue`.
Comparisons are strict; channel differences are signed and luminance uses the
existing integer floor. These facts combine with legacy selectors using AND.
Keep near and far color constraints in separate AND atoms when their tolerances
differ; both use the existing `near` / `not_near` / `tol` fields.

`fill` is `none`, `holes` or `core`; explicit `grow: 0` skips final growth. Closing,
hole filling, optional immutable-core restriction, component-size filtering and
growth follow the source order. `core_grow` defaults to four; explicit zero converges
until stable. An omitted core skips restriction, while an explicit empty core
selects nothing. `clip` and `exclude` apply afterward in canvas-relative coordinates.
Optional `kernel` is empty, `cross` (the default), or `square`. It controls closing,
core growth, erosion and final growth. Square uses all eight surrounding pixels;
cross uses four orthogonal pixels. Hole filling stays four-connected, and component
membership keeps its separate four/eight choice. The crop exterior is false.
Unknown kernels refuse even when no morphology is active. Font-dependent providers
remain outside this contract.

Optional `grow_through` uses the same OR-of-AND selectors on the original pixels.
It admits each newly reached pixel during positive final `grow` only; omitted is
unrestricted, `[]` admits none, and `[[]]` admits every sampled pixel. Existing
selected pixels survive even when they fail admission. `sample_rect` also bounds
this predicate role. Closing, filling, component selection and core growth remain
unchanged; final `clip` and `exclude` still apply afterward. Nonpositive final
growth with admission refuses. The existing predicate work budget includes this
role before evaluation. Constrained growth stops at barriers, unlike unrestricted
growth followed by clipping. Literal synthetic tests cover the historical wedding
top/bottom lettering stages; middle centroid filtering, new glyph coverage and
complete artwork permissions remain unfinished. These two inset fixtures do not
establish arbitrary historical crop-edge parity or complete `raster_rendering.06`.

Default and explicit cross preserve the existing work charge. Square adds
`16 * rect width * rect height` per active morphological pass. Closing counts twice;
a present core counts once, including `core_grow: 0`. Nonzero erosion and final
growth each count once. The limit is checked before predicate or topology work.

Rectangle and pixel masks share one three-stage permission loop, the combined
64-region cap, native-footprint intersection and text protection. A single numerical
owner checks and returns the charged mask-work bound before evaluation. Source
permissions and current-pixel erases share predicate construction; font counters
and erases share binary topology. No runtime Python or dynamic provider imports
are used.

Tables under `profiles/permissions/footprints/` keep permission facts tied to stable
asset IDs. Twelve tables cover thirteen source permission contexts on synthetic inputs;
`mini-g02-g12.json` serves both asset IDs because their operands match exactly.
`mini-t2.json` replaces the former generic-only partial table. Historical partial
expectations stay unchanged inside the source fixture, not as another runtime
source. These are permission contracts, not complete artwork workflows.

Source-based tests retain 14 generic provider records and 19 nested footprints,
seven component/predicate provider records and six flood calls. Complete staged
permission tests cover four additional contexts, including every allow_add and
native-footprint operand. Counts describe these source groups, not full-family
or historical script migration.

The authored authority for the shared panel geometry is
[batch-c-panels.json](profiles/permissions/batch-c-panels.json). The first `allow`
records in `mini_g04.json`, `mini_g09.json`, `mini_g11.json`, `mini-g02-g12.json`
and `mini-g08.json` are flattened copies
of its complete `allow` array, preserving order. They are derived runtime inputs,
not separately authored panel definitions. Self-contained tables keep the
existing one-level resource loader simple.

For a panel revision, change the shared table first, substitute its complete array
for that prefix in all five derived tables, and preserve their remaining records
and mask stages. Update affected size/hash pins through the normal reviewed input
workflow. The existing canonical-table test checks shared-prefix equality and
independent complete original masks; run
`go test -p 2 -run '^(TestCLIDryRunAndApply|TestPilotHistoricalGoldenBytes)$' -count=1 .`.
An intended source revision also needs independent new source expectations before
repinning goldens. The archived Python conversion and original source capsules
record one-time migration lineage; they are not a Go runtime or maintenance
dependency. This finite prefix replacement does not require them.


A footprint may set `sample_rect` inside `rect`. It limits initial main, core and
component-tag predicates; `rect` still bounds topology and output. This permits
selecting artwork inside a crop and growing into neighboring canvas pixels.
Omitting `sample_rect` keeps the existing crop behavior.

Optional `components` requires `connectivity: 4` or `8`. Omitted `seeds` keeps all
foreground components; `seeds: []` keeps none. Seeds are explicit canvas-relative
coordinates inside the sampling rectangle, and every seed must be foreground.
`reject` uses the same OR-of-AND selectors and vetoes an entire component when any
of its pixels matches. Minimum size, seed membership and veto share one traversal
after core restriction and before final growth. Component connectivity does not
change growth or hole filling. Legacy negative-index wrapping is resolved when
converting source recipes, keeping runtime coordinates explicit.

Flood permissions reuse the same owners with `components.background_seed:
"label-zero"`. This requires explicit seeds, no minimum-size filter and no `reject`
field. A background seed selects all original background-label pixels across `rect`,
including disconnected regions and zero padding outside `sample_rect`. Removed
foreground never becomes background. Foreground and background seed selections
union before optional `erode`; zero erosion skips and negative erosion converges.
Erosion follows `kernel` and occurs before final growth and clipping. Original
flood recipes use their crop as `rect`, keeping erosion inside it before placement.
Omitted background policy preserves foreground-seed refusals. Explicit empty seeds
still select nothing; explicit empty rejection criteria stay present and refuse
label-zero mode. Advanced artwork and donor reconstruction remain open.


Batch E permission tables `op_p.json`, `button.json` and `sale.json` cover three
source calls on two declared synthetic 512x512 RGBA contexts. `op_p` stores eleven
literal rectangles. `button` keeps sixteen separate 32x32 crops, selects alpha
strictly above 128, fills four-connected holes, then erodes once with the square
kernel. `sale` selects alpha above 40 and any RGB channel above 90 in the first two
lower bands. Each protection grows by three square layers over the complete
canvas, then clips to its own sign before subtraction. This preserves neighboring
signs when protection crosses a seam. These tables describe permissions, not
complete art workflows or verified dimensions of actual game assets.


### Approved fixed artwork as versioned data

[Fixed-art maintenance](docs/fixed-art.md) describes the existing static PNG import
path for a named already approved image. The canonical [instance record](recipes/artwork/fixed-instances.json)
references source-bound profile, readable source/image/mask data and independent
native/RGBA expectations. Exact-mask and expected-target checks are separate from
runtime coarse rectangles and writer self-integrity. No new renderer or general
art generator is claimed.

The [current-tooling scope amendment](analysis/current-tooling-scope-v3.json) preserves exact accepted-834 history and changes two current obligations without adding Go credit. The [v3 roadmap](analysis/migration-roadmap.md) remains 76/90 proven groups and 10/15 Full families. The next bounded task is source-bound maintenance of the current documented name policy; historical F112 70% is not current, and native replay, ownership and fit remain unproved. Probe work is last.

## Source-bound name cohorts

The shared `reference_cohort` report selects declarative pointer tables, preserves each slot occurrence and measures the first-END stream through existing font and grammar owners. Its explicit historical nominal policy is separate from native advances, source-grid ink and physical fit. An optional source-policy join reuses the instruction index and graph; raw buckets are capped before allocation, and known hazards remain beside UNKNOWN.

Start with the [synthetic runnable example](examples/name-cohort/README.md). The [contract](analysis/name-cohort-contract.json), [proof](evidence/name-cohort-proof.json) and [reviews](evidence/name-cohort-review.json) document the 43 cases, 28 typed refusals, source limits and capability costs. The actual 207-name game census, fixed F112 alias, complete ownership and landing proof remain pending. No new handler, decoder, graph or scale interpreter was added. This is capability growth, not code reduction; coverage remains 10/15 Full and 76/90 proven, and probe work is last.

## Synthetic declarative name-policy replay

The [eleven-record example](examples/name-policy/README.md) exercises existing guarded-word planning and complete synthetic copy readback with no production code change. It preserves source-version boundaries, distinguishes dry-run pin echoes from computed outputs, and grants no native, reduction or migration credit.

Startup centering uses the same planner and copy writer through the
[native guards](recipes/layout/startup-centering-2026-10-01-native.json) and
[four whole slots](recipes/layout/startup-centering-2026-10-01-sent.json).
The [literal fixture](testdata/startup-centering-2026-10-01.json) binds all sixteen
synthetic OLD/DONE combinations to one independently frozen all-NEW target.
The checked-in recipes admit the all-OLD carrier; the tests select only the other
fifteen explicitly pinned identities. They do not accept arbitrary repinned inputs.
Run `go test -run '^(TestPlanAndCopy|TestPlanRefusals)$' -count=1 .` for synthetic
copy, padding, source preservation and refusal checks. All-DONE still creates a
fresh exclusive copy. No production function or stream-control waiver was added.

The six Multitap offsets use source-specific ties-to-even rounding. The first
scaled space becomes C007; the second remains unchanged. Memory prefixes account
for the centered window's origin movement, so C00E moves visible ink by seven
units. These fixed vectors preserve wording, pages and the7002 arguments; they
are not a general renderer model. Retained native slots match the derived NEW
bytes, but original-native OLD replay, complete consumer/interior/boundary
reference admission and a post-patch live capture remain separate proof gates.

Recipe intake now checks ambiguous duplicate root keys before decoding can erase
them, including hidden mixed-operation requests. Valid legacy scalar output and
its selective nested policy remain unchanged. This adds a refusal for ambiguous root configuration, without a new
parser, operation, graph, function or control-waiver flag.
