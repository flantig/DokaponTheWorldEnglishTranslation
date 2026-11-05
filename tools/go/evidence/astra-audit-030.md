# Adversarial audit 030

No reproducible new functional defect or concrete unnecessary helper/split was established in this bounded static audit. This is a findings report, not correctness or integration approval.

Reviewed immutable snapshot `/var/tmp/dokapon-observed-reference-mly_qel2/sealed-final` with manifest SHA-256 `76062d4be7328412ded56c52293408aa55128813c48394d15418b6bddeb6d13f`. All 373 members and all 332 members of audit029’s snapshot verified. All storage keys are normalized and contained; the exact two external aliases are source bindings only. All 35 ordinary-review candidate pins match. Later metadata is separately verified, not retroactively attributed to that review.

The four new named functions have concrete ownership reasons and callers. `normalizeReference` serves expected guards, append and observation; `referenceTarget` serves append and observation. `checkJSON` extracts the existing selective validator, and `auditStreams` owns paired-source report lifecycle while reusing `controls`. No second instruction decoder, ELF mapper, writer or per-patch handler was identified. The registry owner and JSON policy switches remain complexity costs, without a demonstrated need for another abstraction.

Declared observations retain site order, readable/null words, divergent targets and separate full-word versus one-byte target mapping. Expected guards remain observation-free. Sparse struct metadata remains refused; this audit does not establish canonical-input completeness. Observed recipe size is checked after shared `os.ReadFile`/decode (`main.go:98,118`), so the accepted-size cap is not a hard read-work or peak-memory guarantee; no resource-exhaustion probe was run.

All 190 accounting inputs verify. Since audit029, production grew 37,169 bytes and four functions; runtime inputs grew 46,507 bytes including 2,096 recipe bytes, 1,394 template bytes and 5,848 example bytes. Tests grew 46,619 bytes and testdata 107,395 bytes, separately. Current totals: 31 production files / 313,749 bytes / 33 named functions; 109 runtime files / 796,740 bytes. No net reduction or historical retirement credit follows. Coverage remains 5 Full / 9 Partial / 14; historical ledger remains 8 full-Go / 20 explicitly reviewed / 16 partial-reference / 366 other of 410.

Serena caller analysis used an isolated private copy whose Go bytes still match the snapshot. The 251 coverage pins and seven proof source/review pins verify. A scoped, positive-self-checked high-confidence credential scan found no matches in 87 Go/module/recipe/example files. The JSON report contains exact candidate pins, file/line challenges and the private receipt hash.

Skipped: build, vet, tests/race, benchmarks, dynamic probes and protected/native resources; no code was changed. Risk: static review cannot establish full caller, canonical-corpus, runtime or integrated correctness.
