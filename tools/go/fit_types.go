package main

// FitProfile supplies source font facts and declared consumer limits, without patch targets.
// Encoded hashes and measurements are report outputs, never authoring prerequisites.
type FitProfile struct {
	SourceSHA256   string              `json:"source_sha256"`
	SourceSize     int64               `json:"source_size"`
	GlyphmapSHA256 string              `json:"glyphmap_sha256"`
	ISOFile        string              `json:"iso_file,omitempty"`
	ELFVMADelta    string              `json:"elf_vma_delta"`
	Font           Layout              `json:"font"`
	InkAtlas       *RegistryInput      `json:"ink_atlas,omitempty"` // Native font TXD; independent of candidate ELF provenance.
	Boxes          map[string]FitBox   `json:"boxes"`
	Entries        map[string]FitEntry `json:"entries"`
}

type FitBox struct {
	MaxWidth           int    `json:"max_width"`
	MaxLines           int    `json:"max_lines"`
	AllowPages         bool   `json:"allow_pages"`
	Wrap               bool   `json:"wrap,omitempty"`
	MaxBytes           int    `json:"max_bytes,omitempty"`
	RequiredLineBreaks *int   `json:"required_line_breaks,omitempty"` // Includes trailing LINEs; nil leaves the count unconstrained.
	Evidence           string `json:"evidence"`
}

type FitEntry struct {
	Authoring     string          `json:"authoring,omitempty"`
	Source        *AddressRange   `json:"source,omitempty"` // Exact narrative bytes relative to the selected, pinned ELF extent.
	Box           string          `json:"box"`
	NumericBounds []*NumericRange `json:"numeric_bounds,omitempty"`
}

type FitRow struct {
	ID            string     `json:"registry_id"`
	Box           string     `json:"box"`
	English       string     `json:"en"`
	Status        string     `json:"status"`
	EncodedHex    string     `json:"encoded_hex,omitempty"`
	EncodedSHA256 string     `json:"encoded_sha256,omitempty"`
	Bytes         int        `json:"bytes"`
	Width         int        `json:"max_line_width"`
	Lines         int        `json:"max_lines_per_page"`
	LineWidths    [][]int    `json:"line_widths_by_page,omitempty"`
	LineBreaks    *int       `json:"line_breaks,omitempty"` // Absent unless requested and successfully measured; zero is a known count.
	Diagnostics   []string   `json:"diagnostics,omitempty"`
	InkStatus     string     `json:"ink_status,omitempty"`
	InkBounds     [][][4]int `json:"ink_bounds_by_page,omitempty"`
	InkDiagnostic string     `json:"ink_diagnostic,omitempty"`
}

type FitReport struct {
	Operation      string            `json:"operation"`
	SourceSHA256   string            `json:"source_sha256"`
	RegistrySHA256 string            `json:"registry_sha256"`
	GlyphmapSHA256 string            `json:"glyphmap_sha256"`
	ProfileSHA256  string            `json:"profile_sha256"`
	Measurement    string            `json:"measurement"`
	InkAtlasSHA256 string            `json:"ink_atlas_sha256,omitempty"`
	InkAtlasSize   int64             `json:"ink_atlas_size,omitempty"`
	Limits         string            `json:"limits"`
	Boxes          map[string]FitBox `json:"boxes"`
	Entries        []FitRow          `json:"entries"`
}
