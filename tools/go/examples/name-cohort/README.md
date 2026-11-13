# Source-bound name cohort example

Run from tools/go:

```sh
go run . --source examples/name-cohort/source.elf --recipes examples/name-cohort/profile.json
```

All bytes are synthetic. The selected pointer slot is 0x101804, pointing to the
four-byte SENT input. The result preserves that occurrence, reports one line of
nominal width 20, and checks its declared raw-pointer bucket. The native exception
for glyph 1 would advance 3; this explicit historical nominal policy advances 20.
These units are neither atlas pixels nor proof of screen fit.

`registry_inputs.sentinel` reuses the shared path/size/SHA256 input descriptor.
Its relative path is resolved beside the profile. No canonical registry or
glyphmap is required. Profiles and inputs are rechecked before JSON is published.
Apply, registry and glyphmap arguments are refused on this route.

Table start/end addresses select little-endian pointer slots, and end is exclusive.
`occurrence` is zero-based within the selected table, while `id` retains the exact
slot VMA. Equal target pointers keep separate rows. Target word reads may be odd
when two bytes exist, but pointer slots require explicit four-byte alignment.
The complete first-END slice is measured with LINE resets, retaining empty lines.

The optional source-policy result is separate from the nominal comparison. Its
eligible-under-declared-policy label describes these synthetic buckets only.
Out-of-scope, unsupported, incoming and bounded graph paths remain unknown. Raw
buckets retain at most 256 sites per target, plus bounded first hazard witnesses;
a limited prefix never proves complete ownership. Known hazards still refuse.
No alias write, loaded SENT capacity, safe landing, actual 207-name census,
whole-program ownership, native execution or physical fit is established.

See the [contract](../../analysis/name-cohort-contract.json),
[proof](../../evidence/name-cohort-proof.json) and
[reviews](../../evidence/name-cohort-review.json).
