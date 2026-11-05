# Astra audit 028 — integrated toolkit boundary

**LOW — stale architecture extension guide** (`ARCHITECTURE.md:143`, `:159`; `ARCHITECTURE.html:423`, `:425`). Both still describe registry policy/publication inside `run` and direct extensions there; current `run` dispatches to `authorRegistry`. The guide also retains19/368 historical counts and omits the newer fit, raster/texture and snapshot owners. Update it or explicitly supersede it with the planned14-owner map, keeping one current source of ownership/count facts. Root was notified; later documentation changes are outside this frozen review.

No reproducible functional defect or justified extra split/helper was established in the bounded inspection. The14 availability claim is defensible only for the named narrow operations: reconciliation is selected advisory content/reference comparison, and asset preview is actual PNG export. Neither implies complete reconciliation, inventory/contact sheets/spec generation, or Full family coverage. The forthcoming extension map should preserve those distinctions.

Independent static checks verify all78 source/data pins,28 named functions across26 production files, and94 native runtime files totaling731,954B. The registry extraction is mapped-body identical (`a551673ad43bfc4a84ccd19a1937f2df300bf9e87b8e9d56bbfd8cf2be852e82`) and adds568B over the accepted snapshot. Since audit027, runtime grows30,016B (25,212B Go +4,804B profiles); test source grows29,118B separately. These are costs, not deletion or reuse savings. Frozen official accounting intentionally predates extraction.

The immutable source is `/var/tmp/dokapon-astra028-gm5ohfri/source`; its175-file manifest and static receipts are hashed in `astra-audit-028.json`. Prior027 top-level Go pins were checked against its immutable snapshot. Serena owner/caller analysis was cross-checked with frozen source. Root reports integrated race145.271s and required-check passes; this audit did not independently rerun them.

This report supplies findings only and grants no integration, coverage promotion, retirement or application approval.

Skipped: dynamic suites/build/vet/mutations, exhaustive historical coverage and post-snapshot documentation review; no production/tests/profiles or protected resources touched.
Risk: bounded negative findings do not establish arbitrary-input, runtime/gameplay, visual or real-image correctness.
