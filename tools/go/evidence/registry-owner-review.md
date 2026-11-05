What this change does: Moves the existing registry document/report workflow out of CLI routing into `authorRegistry`. Options replace four captured flag pointers; existing statements and policy remain unchanged.

No material findings. Independent mapped-body comparison is **exact** (SHA256 `a551673ad43bfc4a84ccd19a1937f2df300bf9e87b8e9d56bbfd8cf2be852e82`), and `run` outside the branch is exact after import partition. Existing registry types and tests are unchanged. The sole caller retains nonempty-table/source preflight and source ownership; the separately opened derived registry closes before the borrowed source as before. The new nil `err` matches the prior branch-entry state. Error and publication order are preserved.

The owner is coherent: routing, bounded reads, grammar scanning and binary patch planning remain separate responsibilities. This is a useful boundary, not a claim of reduced code or reduced algorithmic complexity.

Focused `TestCLIDryRunAndApply` **PASS 7.641s**, build **PASS**, all **78 pins** held before/after; nice19/GOMAXPROCS2/-p2/owned TMPDIR. Private receipt: `/var/tmp/dokapon-registry-owner-review-cratqgv5/receipt.json`, SHA256 `7c16fa2350034a4a0e41810586d307fa7d42f18104cabde8ceacfb50918a9e71`. Independent equivalence details: `/var/tmp/dokapon-registry-owner-review-cratqgv5/equivalence.json`, SHA256 `9b917e7cfe08499cd7881796b131bc02bafb45ed0d393ae649a0f6cac17de2bd`.

Full suite/race/227 corpus/mutants remain deferred to the integrated checkpoint. No production/test changes, protected resource access, new grammar/policy or family/retirement approval.
