# Astra audit 027 — frozen native raster candidate

**LOW — separate mode-specific guards in `composeCells`** (`raster.go:28`, `:41`, `:51`). These predicates mix common checks with repeated metric/nonmetric alternatives. Tracing font metrics, bearing, advance and tile dimensions requires reconstructing both branches and operator precedence in each expression. Keep the existing owner, but separate common guards from explicit metric/else guards. Preserve messages, refusal order and validation; add no function, adapter or dependency. This is a readability finding, not a demonstrated functional defect.

Root accepted this finding and plans the small guard refactor. Its implementation and later verification are outside this read-only report.

The authoritative source is `/var/tmp/dokapon-astra027-u3_b_5su/source`, bound by `astra-audit-027-pins.json` SHA256 `4af9dfc3d46fb2d2a54dfe2ba966e575532fbc255de1f8ac95b8f62550f351a9`. All249 source pins matched before and after focused testing; all156 candidate accounting records matched their bytes/hashes, and the group deltas were independently recomputed. Serena references were cross-checked against the frozen source.

Focused existing historical-golden and standalone-texture CLI tests passed in7.191s with nice19, GOMAXPROCS2/-p2 and owned disk temporary storage. Complete runtime grows36,328B from the accepted resizer checkpoint:13,352B Go,21,456B shared font data and1,520B profile. Tests15,377B and fixtures212,458B are separate. Since026 runtime grows60,638B. There are26 named production functions. None of these costs establish reduction, retirement or Full coverage; core coverage stays4/14=28.57% and raster stays Partial.

No further reproducible defect or justified consolidation/deletion finding was established. The new run layer shares the existing resampler, compositor containment and authoring/publication route; the exact pixel formula has two actual production contexts. The selected rule does not prove all discovered styles or callers.

The disclosed4-to8 counter-connectivity mutant surviving the selected-rule golden remains a frozen-snapshot test limitation. Root reports a new independent diagonal fixture is being added after quiescence; that later fixture and the planned readability edit were not reviewed here. This report supplies findings only and grants no integration or promotion approval.

Detailed check receipts and SHA256 hashes are recorded in `astra-audit-027.json` under `/var/tmp/dokapon-astra027-checks-2zz2wmwz`.

Skipped: no repeat full race/build/vet, full historical-corpus audit, or post-snapshot fix review. No source/test/fixture, protected ISO/registry, owner emulator or authentication resources were changed or controlled.
Risk: bounded negative findings do not establish arbitrary font/style, visual/gameplay, or ISO-application correctness.
