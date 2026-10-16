# Translation registry

`string-registry.json` is the project's canonical per-line translation record.
Its top-level `entries` array contains 5,544 records with stable `id` values.
`glossary.json` contains shared terminology and naming decisions.

Useful fields include:

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier, often the original game address |
| `jp` / `en` | Source Japanese and English translation |
| `chapter`, `character`, `event` | Where the text is used |
| `note` | Translation, spacing, alignment and implementation decisions |
| `status` | The recorded verification stage, not a blanket completion claim |
| `ref_sites`, `landing_vma`, `patch_ref` | Technical provenance where available |

English fields can include control notation, substitutions and line/page markers.
Preserve those when proposing wording changes; they are not ordinary prose.
Retain stable IDs and consult shared terms in the glossary. Image-only labels
are tracked separately in [the image inventory](../images/manifest.json).

The JSON files are copied byte-for-byte from the active development registry.
Their exported SHA-256 values are recorded in the image manifest. Legacy paths
in notes are development-workspace references, not necessarily links in this
repository. This snapshot is for review and collaboration; it is not a patch
installer or proof of complete runtime verification.
