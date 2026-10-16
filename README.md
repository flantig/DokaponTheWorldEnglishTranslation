# Dokapon the World English Translation

English translation data and translated image assets for the PlayStation 2 game
Dokapon the World.

- [Translation registry](registry/string-registry.json): 5,544 source/translation
  records, with implementation notes and verification status.
- [Terminology glossary](registry/glossary.json): shared names and terminology.
- [Translated images](images/): 224 PNGs organized by their role in the game.
- [Image manifest](images/manifest.json): source locations, dimensions and hashes.

## Snapshot status

This October 16, 2026 snapshot corresponds to translation build `817962e2`.
The PNGs are exact decoded exports of the applied textures, including the latest
Jankie rule card, Dokapon King Cup titles, revised commemorative caption,
SURVIVE and NOT30 alignment, and Strike/Give Up battle diagrams.

Applied or statically verified does not mean every line or screen has passed
in-game review. The registry preserves each entry's actual status; the image
manifest records incomplete native visual coverage. Some translation is baked
into images rather than represented by a registry string.

This is a data and artwork repository, not yet a standalone ISO patcher or a
complete copy of the development workspace. Historical tool/document paths in
registry notes and manifest provenance refer to that workspace and may not exist
in this repository. Future translation changes require another deliberate sync;
the local workspace is not automatically mirrored here.

## Included and excluded files

Only the current registry, glossary, applied translated PNGs and their inventory
are included. Unapplied font experiments, superseded image comparisons, custom
character artwork, probe screenshots and emulator files are excluded.

No game disc images, executables, save data or BIOS files are distributed.
The translated textures contain original game artwork; rights to that artwork
and the game remain with their respective owners.
