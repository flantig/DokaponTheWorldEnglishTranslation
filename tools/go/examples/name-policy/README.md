# Synthetic name-policy replay

This example expresses the eleven public October 22 F172/F173 records through
existing `guarded_words` recipes. It adds data and tests, with no production Go
change, new handler or new transaction mechanism.

Run from `tools/go`:

```sh
go test -run '^(TestCLIDryRunAndApply|TestPilotHistoricalGoldenBytes)$' .
```

The existing CLI test creates a temporary 5,087,232-byte carrier filled with CC,
overlays the [independent public literals](../../testdata/name-policy-2026-10-22.json),
and runs the [native mapping](../../recipes/layout/name-policy-2026-10-22-native.json)
and [SENT mapping](../../recipes/layout/name-policy-2026-10-22-sent.json) in both
argument orders. No game binary is included. The source and complete after-image
were independently constructed and hashed before candidate Go execution.

Both recipes share one carrier identity and complete output pin. Their mappings
are separate: native VMA minus 0xfff80, or physical trailer 0x43a000 plus SENT VMA
minus 0x04000000. The unchanged LUI at 0x4ac40c remains an explicit guard. Its
encoded immediate is 0x0008; an isolated instruction pair does not prove a native
pointer or ownership contract.

The suite checks every ID, old/new span and offset, all unchanged carrier bytes,
624 declared bytes, 161 changed bytes, input preservation and refusal cleanup.
A dry run merely echoes `expected_output_sha256`. Applying either table alone
fails the complete output pin. Applying both produces the independent entire
after-image; existing outputs cannot be overwritten. Exact eleven-record package
membership is independently tested, rather than promised by the generic planner.

The dated records include ordinary names at 60%, six-row names at 56% and a local
46% Sickle alias. Their outer templates balance signed unscaled Y+5/-5 and restore
100%. These are source-declared control values, not native rounding or screen-fit
measurements. They are a subset of the October 22 116-edit stage, not its full ISO
result, the later October 25/28 changes or the latest translation. October 28's
70% concerns prices. These synthetic recipes cannot be repinned as native approval.

See the [contract](../../analysis/name-policy-replay-contract.json),
[proof](../../evidence/name-policy-replay-proof.json) and
[reviews](../../evidence/name-policy-replay-review.json). Native source replay,
ownership, landing/capacity, ABI, actual fit and latest-source compatibility remain
separate obligations. Coverage stays 10/15 Full and 76/90; probe work remains last.
