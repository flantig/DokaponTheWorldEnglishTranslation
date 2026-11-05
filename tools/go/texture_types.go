package main

// TextureProfile selects standalone TXD authoring or an extracted-CMB manifest.
// With no operation, omitting PNG and Render exports; otherwise pinned pixels or
// bitmap cells replace the selected raster. Inventory only reads raw headers.
type TextureProfile struct {
	Operation      string                          `json:"operation,omitempty"` // Empty authors one raster; inventory/specification are read-only; manifest packages previews.
	SourceSHA256   string                          `json:"source_sha256"`
	SourceSize     int64                           `json:"source_size"`
	Texture        string                          `json:"texture"`
	PNG            string                          `json:"png,omitempty"`
	PNGSHA256      string                          `json:"png_sha256,omitempty"`
	Rectangles     [][]int                         `json:"rectangles,omitempty"`
	PalettePolicy  string                          `json:"palette_policy,omitempty"` // Empty preserves; source snaps to used source colors; exact/quantize regenerate CLUT.
	PixelPolicy    string                          `json:"pixel_policy,omitempty"`   // rgba permits color in calibrated direct32 modes; empty keeps font guards.
	Evidence       string                          `json:"evidence"`
	Render         *RasterRender                   `json:"render,omitempty"`
	Specifications map[string]TextureSpecification `json:"specifications,omitempty"`
	Archive        string                          `json:"archive,omitempty"`
	IndexSHA256    string                          `json:"index_sha256,omitempty"`
	Preview        *TexturePreview                 `json:"preview,omitempty"`
	Contacts       *TextureContacts                `json:"contacts,omitempty"`
}

// TexturePreview controls presentation only. Crop is shared XYWH in source pixels;
// it may extend outside either source and pads with transparent pixels.
type TexturePreview struct {
	Scale  int            `json:"scale"`
	Crop   []int          `json:"crop,omitempty"`
	Layout string         `json:"layout,omitempty"`
	Font   *RegistryInput `json:"font,omitempty"`
}

// TexturePairLayout holds observed presentation facts, separate from patch recipes.
// Captioned strips render at native size before scaling the complete canvas.
type TexturePairLayout struct {
	Background uint8    `json:"background"`
	Checker    []uint8  `json:"checker,omitempty"`
	Tile       int      `json:"tile,omitempty"`
	Gap        int      `json:"gap,omitempty"`
	GapSpace   string   `json:"gap_space,omitempty"`
	PNGMode    string   `json:"png_mode"`
	Canvas     [2]int   `json:"canvas,omitempty"`
	Crop       []int    `json:"crop,omitempty"`
	PanelY     [2]int   `json:"panel_y,omitempty"`
	Labels     []string `json:"labels,omitempty"`
	LabelAt    [][2]int `json:"label_at,omitempty"`
	Ink        [3]uint8 `json:"ink,omitempty"`
	FontSize   int      `json:"font_size,omitempty"`
	FontLayout string   `json:"font_layout,omitempty"`
}

// TextureSpecification keeps authored facts separate from measured source data.
// Archive/Entry are declared labels; only the standalone source pin is verified.
type TextureSpecification struct {
	Texture     string `json:"texture"`
	Archive     string `json:"archive"`
	Entry       string `json:"entry"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	JPText      string `json:"jp_text"`
	ProposedEN  string `json:"proposed_en"`
	Difficulty  string `json:"difficulty"`
	ScreenHint  string `json:"screen_hint"`
	Notes       string `json:"notes"`
}

type TextureSpecificationRow struct {
	ID              string               `json:"asset_id"`
	NativeOrdinal   int                  `json:"native_ordinal"`
	Specification   TextureSpecification `json:"specification"`
	Header          *TextureHeader       `json:"header"`
	DecodedStatus   string               `json:"decoded_status"`
	DecodedGeometry *[2]int              `json:"decoded_geometry"`
	DecodedFormat   string               `json:"decoded_format,omitempty"`
	RGBASHA256      *string              `json:"rgba_sha256"`
	Diagnostic      string               `json:"diagnostic,omitempty"`
}

// TextureIndex preserves native order and duplicate names. Metadata errors belong
// to individual entries; structural dictionary/envelope errors reject the index.
type TextureIndex struct {
	Textures   []NativeTexture `json:"textures"`
	chunkCount int
	byName     map[string][]int
	source     []byte // Read-only source view; codec reuse cannot cross member buffers.
}

// NativeTexture describes declared metadata, not calibrated codec support.
type NativeTexture struct {
	Name          string         `json:"name"`
	Header        *TextureHeader `json:"header,omitempty"`
	MetadataError string         `json:"metadata_error,omitempty"`

	infoStart, infoEnd, pixelStart, pixelEnd, chunkCount int
}

type TextureHeader struct {
	Width        uint32 `json:"width"`
	Height       uint32 `json:"height"`
	Depth        uint32 `json:"depth"`
	RasterFormat uint16 `json:"raster_format"`
	Version      uint16 `json:"version"`
}

// TextureDiscovery records source-backed advisory measurements, never text identity.
// Unavailable means an evaluated failure; imported not_evaluated records have no
// detector result. Both keep Score nil, without conflating contact eligibility.
type TextureDiscovery struct {
	Tier        string                 `json:"tier"`
	Status      string                 `json:"status"`
	Score       *TextureDiscoveryScore `json:"score"`
	FlagReasons []string               `json:"flag_reasons"`
	Diagnostic  string                 `json:"diagnostic,omitempty"`
}

type TextureDiscoveryScore struct {
	GlyphClusters         int     `json:"glyph_clusters"`
	ClusterFraction       float64 `json:"cluster_fraction"`
	GlyphTiles            int     `json:"glyph_tiles"`
	DominantColorFraction float64 `json:"dominant_color_fraction"`
	OpaqueFraction        float64 `json:"opaque_fraction"`
	TextLineRows          int     `json:"text_line_rows"`
}

// TextureManifest preserves one entry per CMB index record, including failures.
// Preview paths are relative to the single contained output ZIP.
type TextureManifest struct {
	Archive       string                 `json:"archive"`
	SourceSHA256  string                 `json:"source_sha256"`
	SourceSize    int64                  `json:"source_size"`
	IndexSHA256   string                 `json:"index_sha256"`
	ProfileSHA256 string                 `json:"profile_sha256"`
	PNGConversion string                 `json:"raw_png_rgba_conversion"`
	Entries       []TextureManifestEntry `json:"entries"`
	Limits        string                 `json:"limits"`
}

type TextureManifestEntry struct {
	Ordinal      int                     `json:"ordinal"`
	Name         string                  `json:"name"`
	SourceRange  [2]int64                `json:"source_file_range"`
	SourceSHA256 string                  `json:"source_sha256"`
	SourceSize   int64                   `json:"source_size"`
	Status       string                  `json:"status"`
	Diagnostic   string                  `json:"diagnostic,omitempty"`
	Rasters      []TextureManifestRaster `json:"rasters"`
}

type TextureManifestRaster struct {
	TextureSpecificationRow
	Discovery     TextureDiscovery `json:"discovery"`
	Preview       string           `json:"preview,omitempty"`
	PreviewSHA256 string           `json:"preview_sha256,omitempty"`
}

// TextureContacts merges pinned extracted manifests in declared input order.
// Font is explicit pinned bytes; neither this operation nor the backend searches fonts.
type TextureContacts struct {
	Font    RegistryInput   `json:"font"`
	Sources []RegistryInput `json:"sources,omitempty"`
}

// TextureContactRow retains every source row, including failed/undetected assets.
// Key uses collection/entry/native ordinals; Sheet is the final page link, including duplicates.
type TextureContactRow struct {
	Key             string                 `json:"key"`
	Archive         string                 `json:"archive"`
	Entry           string                 `json:"entry"`
	EntryOrdinal    int                    `json:"entry_ordinal"`
	EntryStatus     string                 `json:"entry_status"`
	EntryDiagnostic string                 `json:"entry_diagnostic,omitempty"`
	Raster          *TextureManifestRaster `json:"raster"`
	Sheet           string                 `json:"sheet"`
}
