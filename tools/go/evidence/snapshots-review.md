What this change does: Adds an opaque-artifact snapshot lifecycle and a shared streaming publisher with mandatory size/hash checks. Revised receipt I/O reuses existing `readInput`; snapshot ownership retains explicit nonsymlink and strict one-value JSON validation.

No material code findings. The revision changes only `snapshots.go` bounded receipt I/O and `analysis/snapshot-reuse-decision.json` reuse/cost wording. It removes duplicated reading/closing checks and gains existing size/mtime stability checks. The three-payload-pass description is now accurate. First-review reports/receipts remain superseded in `/var/tmp/dokapon-snapshots-review-1eymx6sq/pre-reuse` and its parent.

Revised focused `TestCLIDryRunAndApply` **PASS 4.626s**, build **PASS**, all **76 pins** held before/after. The exact same **9** independent CLI checks were rerun against the revised binary: **2 MiB** preview/create/list/restore, byte/source identity/mtime preservation, duplicate/overwrite refusal, same-size corruption and static source-symlink refusal. No cases were added.

Receipt-last publication, honest nonhashing inventory, new-output-only restore and inode-owned publisher cleanup remain coherent. Reserved incomplete tags and lack of atomic/hostile-concurrency guarantees remain explicit limits.

Private revised receipt: `/var/tmp/dokapon-snapshots-review-1eymx6sq/receipt-revised.json`, SHA256 `d9c4a5b331bc5b71c4115f862799b32fa8a322251ff4708039cfff3bba30e7ed`. CLI details: `/var/tmp/dokapon-snapshots-review-1eymx6sq/revised-cli/cli-probe.json`, SHA256 `f7fef5cb9b00c640d83ab4856e8fc0e03afc810190bb95c250738d32cc2d2d06`.

Full suite/race/227 corpus/mutants remain deliberately deferred. No protected resource access, implementation edits or broader family/retirement approval.
