Read-only recommendation: a single controlled `texture(..., nil, nil, "")` selfcall is reasonable reuse for source-color discovery. Gate it behind validated indexed-import policy and document one-level termination. Keep the existing GS walk and writer; do not add a helper or second decoder.

The proposed direct sourceRGBA→palette-index mapping is insufficient. Original `E.snap` uses **integer**, not float32, weighted distance over lexicographically sorted colors actually present in the source image. The existing native quantizer then makes another decision over the full native palette. Alpha0 and integer-floor ties can select an earlier nonidentical entry, so the second nearest search must remain.

After snapping, re-check equality with the pixel’s originalRGBA to preserve duplicate indices. Check raw off-mask edits before snapping, so a change cannot disappear into an accepted no-op. Exclude unused CLUT entries from first-stage eligibility; retain them in the second native search. Keep default policy and its4096-color refusal unchanged, without unnecessarily imposing that refusal on source snapping.

Required independent cases include the actual opaque tie, unused palette entries, duplicate-index snap-back, transparent/low-alpha ties, off-mask snap-back and more than4096 candidate colors. No implementation, family or ISO approval is supplied.
