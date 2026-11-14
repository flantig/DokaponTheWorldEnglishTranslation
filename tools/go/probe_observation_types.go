package main

// ProbeObservationTable separates immutable source expectations from acquired facts.
type ProbeObservationTable struct {
	Version int                            `json:"version"`
	Rows    map[string]ProbeObservationRow `json:"rows"`
}

type ProbeObservationRow struct {
	Kind                      string             `json:"kind"`
	RecipeID                  string             `json:"recipe_id"`
	RecipeSHA256              string             `json:"recipe_sha256"`
	SpanBytes                 int                `json:"span_bytes"`
	Cells                     int                `json:"cells"`
	CellWords                 int                `json:"cell_words"`
	SourceSpanSHA256          string             `json:"source_span_sha256"`
	ComparisonSourceSHA256    string             `json:"comparison_source_sha256"`
	GlyphmapSHA256            string             `json:"glyphmap_sha256"`
	HistoricalStaticISOSHA256 string             `json:"historical_static_iso_sha256"`
	SourceISOSHA256           string             `json:"source_iso_sha256"`
	Capacity                  *ProbeCapacitySpec `json:"capacity,omitempty"`
	Limits                    string             `json:"limits"`
	Authority                 string             `json:"authority,omitempty"`
}

type ProbeCapacitySpec struct {
	ISOELFOffset   string `json:"iso_elf_offset"`
	ELFVMADelta    string `json:"elf_vma_delta"`
	Stream         Stream `json:"stream"`
	LoaderBytes    uint64 `json:"loader_bytes"`
	WindowBytes    uint64 `json:"window_bytes"`
	ArtifactOffset int64  `json:"artifact_offset"`
	ArtifactBytes  int64  `json:"artifact_bytes"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ArtifactUsed   int64  `json:"artifact_used"`
	ArtifactCursor int64  `json:"artifact_cursor"`
}

// ProbeCapacityArtifact is a measured serialized ISO extent, never RAM usage.
type ProbeCapacityArtifact struct {
	Source RegistryInput `json:"source"`
	Offset int64         `json:"offset"`
	Bytes  int64         `json:"bytes"`
	SHA256 string        `json:"sha256"`
	Used   int64         `json:"used"`
	Cursor int64         `json:"cursor"`
}

type ProbeCapacityObservation struct {
	Contract          string                   `json:"contract"`
	Actual            []ProbeMemoryObservation `json:"actual"`
	Artifact          *ProbeCapacityArtifact   `json:"artifact"`
	RuntimeAllocation *uint64                  `json:"runtime_allocation,omitempty"`
	RuntimeUsed       *uint64                  `json:"runtime_used,omitempty"`
}
