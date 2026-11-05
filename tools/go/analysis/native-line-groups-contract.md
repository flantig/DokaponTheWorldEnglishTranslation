# Native line-group reuse contract

Recommendation: enhance `composeCells` for group fitting, leading and ordered composition; enhance `renderRuns` with chosen-size/width metadata and alignment before origin rounding. No new function is needed. This is a read-only contract, not implementation or approval.

The existing 17-spec census has 40 line operations, 13 multiline, six with icons and six left aligned. Eleven multiline operations are icon free. All historical multiline cases already fit at requested size or begin at their minimum; the new width/height/minimum-stop boxes are explicitly adversarial.

Nine independent canonical vectors freeze actual two-line mixed runs, actual three-line minimum, actual left alignment, actual single-line icon, constrained width, constrained height, minimum height stop, overlapping lines and top alignment. Word/placed float32, rounded word, whole PANEL candidate, raw-alpha mask, source members and hashes are in the private manifest. These are raster oracles, not whole translated-TXD claims.

Probe each line at a safe cell anchor and read chosen size/width; take the smallest width-fit size, then apply the common height quarter-step using original leading/requested-size ratio. Stop at minimum without inventing a fit refusal. Rerender every line at its exact final anchor with Size=MinSize=chosen. Do not shift previously rounded origins. Independently derived two-pass fit equals canonical selection in all nine cases.

Keep approved Rect, background paint Rect and fit Box separate. Optional absolute BackgroundRect defaults to approved Rect and must nest inside it. Fresh independent reconstruction with approved `[124,84,385,26]`, paint `[125,84,384,26]`, and original source under the positive x124 fringe gives original TXD `8931937b228c6bf337e4f98b096812cca4a684fff95fe8bbbe995da05c691d93`, RGBA `87598b6e4a47c2fdd9bf488f5dbca40b25326662ff65cd9d218f4dc9f7e867e7`, exactly 6411 native byte changes. Expanding paint changes the operation. Prior frozen reports are untouched.

Compose lines sequentially onto the same byte tile, round after each float-over operation, and validate each raw-alpha support against the approved mask. A merged-float-layer mutant differs by 354 pixels on the overlapping-lines vector. Default Pillow composition retains existing policy.

Proposed group data: relative Box, Lines of existing runs, requested Leading, Align (center/left), VerticalAlign (middle/top); shared Layout retains font/style/minimum. Add Size/Width result metadata to BitmapLayer. Existing scalar cells remain unchanged. No helper, measure-only mode or perpatch handler is justified. One probe plus one final rendering per line is the initial cost; benchmark after implementation.

The real icon vector binds fixed advance and direct ORIGINAL pixel paste after line composition, but icon run/schema integration and donor reconstruction are a separate increment. No family promotion, retirement, ISO or native-visual claim follows.

Private bundle: `/var/tmp/dokapon-native-line-groups-6yl96tru/native-line-groups-oracles.zip`, SHA-256 `e476e6ef6c51d3e8d5ebf1d820803cc17974620e9cc88376db7ac26ac07ba7ed`. Full pins, case paths, source/member hashes, bounds, formulas and manifest are in the JSON companion.
