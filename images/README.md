# Translated images

These 224 full-size PNG textures are exported from the applied English build,
not copied from older preview folders. Every PNG was decoded from the current
game data, checked against its saved pixels, and confirmed to differ from the
pristine Japanese texture. The game itself is not included.

| Folder | Images |
| --- | ---: |
| [Map area banners](map-areas/) | 10 |
| [HUD and menus](hud-and-menus/) | 20 |
| [Tutorial explainers](tutorials/) | 7 |
| [Minigame rules](minigame-rules/) | 12 |
| [Minigame titles](minigame-titles/) | 9 |
| [Awards](awards/) | 11 |
| [World event banners](world-events/) | 78 |
| [Title and map logos](title-and-map-logos/) | 3 |
| [Town, shop and dungeon plates](map-plates/) | 74 |

The [manifest](manifest.json) records each PNG's archive, entry, texture name,
dimensions, existing pixel/palette hashes and exported-file hash. Its
`source_spec` paths identify development-workspace provenance; source tools and
specs are not part of this initial publication.

All changed TXD entries across the six graphics archives were accounted for.
The runtime glyph atlas `system/font.txd` is excluded: it supports text rendering
rather than being one of these translated image assets. Unapplied extracted-font
map-plate candidates, font experiments, comparisons and unrelated sprite exports
are also excluded. The published plates are the versions actually in the build.

Some exported texture sheets contain multiple sprites, transparent space or
untouched original artwork. They are storage textures, not necessarily the final
screen layout; the game may tint, crop or composite them. Applied status does
not guarantee every screen has been visually verified in-game.

Source build SHA-256:
`817962e211e7d17fa2d04383c3b698a275ee41e114900743bf1fceca554226c3`.
