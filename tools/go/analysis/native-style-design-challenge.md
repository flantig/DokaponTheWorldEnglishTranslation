Read-only design challenge: enhance existing `renderRuns` and `composeCells`; no new function is warranted.

Prefer one authoritative `BitmapLayer{Rect, Pix []float32}` and the existing origin result. Preserve byte quantization before LANCZOS, but retain final area floats until explicit recipe composition. Default Pillow quantizes per pixel then uses `pixelOver`; opt-in float matches original `op_text` float32 composition before final rint. This distinction is required: four rounded word/layer matches do not establish 113 original caller outputs. Keep the old byte/TXD assertions and add independent raw-float assertions. Containment must use raw positive alpha for float and rounded positive alpha for the old Pillow path.

Three concrete traps matter. Original “black” is an algorithm role, rather than RGB equality. Black+glyph needs binary coverage, fixed r8 counter inner rim and final counter clearing; the current unconditional counter skip is insufficient. Tracking changes both measurement association and cross-run drawing: add tracking after each run sum, subtract it once overall, use a continuous cursor only for nonzero tracking. Validate positive fitted glyph increments.

Normalize the old scalar stroke once, preserving zero-radius glyph-layer semantics. Keep at most two authored layers in order, reject conflicting/ignored fields, require finite supported radii and opaque numeric colors. MinSize defaults to6 and needs the actual caller’s quarter-step bounds. Source-specific observed caps are preferable to unexplained broad support.

Radius15 has749 disk taps: the1M workspace limit alone permits over1.5b visits for two layers. Measure the four actual maximum cases before optimization; constant-color strokes need no nearest-color search. Reuse bounded offsets within the existing owner if measurement justifies it.

This is design guidance, not implementation or family approval. Another worker owns the independent style/float oracles; no source/tests/fixtures or protected assets were changed.
