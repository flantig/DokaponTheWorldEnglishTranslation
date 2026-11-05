What this change does: Shared native line groups fit all lines at one size and compose them in source order. Existing single-line and pixel-font paths retain their owners.

No material findings in this focused review. `composeCells` owns group orchestration without duplicating `renderRuns` fitting/rasterization. Fit box, approved writes and background paint stay separate; final anchors are rerendered before containment checks. Ordered composition uses a uint8 destination after each line. Finite inputs, line counts, workspace and aggregate direct-disc work remain bounded.

Focused `TestPilotHistoricalGoldenBytes` passed in **11.348s** with nice19, GOMAXPROCS2, -p2 and owned TMPDIR. All **73 pins** held before/after. Eight repository raw candidates equal precode independent arrays; the independent actual help01 oracle matches the complete TXD and decoded RGBA. Its ledger reconstructs **11,735** changes, preserves header/CLUT and has zero raw RGBA changes outside the approved mask. Existing single-style/HUD/source-color/resize goldens also passed.

Private receipt: `/var/tmp/dokapon-line-groups-review-osgic4xx/final-receipt.json`, SHA256 `686a59b73d045dd1987c6c4221cff2198be6484171d7c67e00f2a2a1b15cf159`. Oracle bindings: same directory `oracle-bindings.json`, SHA256 `9baf38ed3091ca116646be3232441b4e075ebcdf04b6f6fd748b0f186522a894`.

Full suite/race/227 corpus/mutants were deliberately deferred; CLI validation belongs to the parent receipt. No maximum-profile benchmark, exhaustive historical coverage, family completion or ISO/native visual approval is claimed. No source/test/fixture edits were made.
