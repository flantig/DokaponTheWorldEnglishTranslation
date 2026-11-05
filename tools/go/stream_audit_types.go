package main

// StreamAuditProfile compares declared file windows; it never infers live references.
type StreamAuditProfile struct {
	Sentinel       *SentinelLayout             `json:"sentinel,omitempty"`
	Evidence       string                      `json:"evidence"`
	ObservedFamily string                      `json:"observed_family,omitempty"`
	Sources        map[string]RegistryInput    `json:"sources"`
	Entries        map[string]StreamAuditEntry `json:"entries"`
}

type StreamAuditEntry struct {
	LineLimit *int                   `json:"line_limit,omitempty"`
	ReadPins  map[string]TextReadPin `json:"read_pins,omitempty"`
	Review    *StreamAuditReview     `json:"review,omitempty"`
	Reference AddressRange           `json:"reference"`
	Observed  AddressRange           `json:"observed"`
	Decoder   string                 `json:"decoder"`
	Canonical *StreamAuditPolicy     `json:"canonical,omitempty"`
}

// StreamAuditReview records editorial scope for these pinned inputs, not byte proof.
// Omitted review holds the row whenever another entry requests reconciliation.
type StreamAuditReview struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// StreamAuditReconciliation suggests bookkeeping only; it never grants write authority.
// Unchanged means no status promotion, not that all registry metadata is correct.
type StreamAuditReconciliation struct {
	CurrentStatus         *string            `json:"current_status"`
	Review                *StreamAuditReview `json:"review"`
	Status                string             `json:"status"`
	Reasons               []string           `json:"reasons"`
	ProposedMachineFields map[string]string  `json:"proposed_machine_fields,omitempty"`
}

// StreamAuditPolicy declares source-context authoring, not native box geometry.
// None means no automatic wrapping; characters requires explicit columns and rows.
// Authoring defaults to markers; plain copies leading colour and rejects any {{.
// Ordered consumes every source control occurrence, retaining opaque payloads.
// Fixed16 uses none without Authoring: literal glyphs, then exact zero padding.
type StreamAuditPolicy struct {
	Authoring string `json:"authoring,omitempty"`
	Wrap      string `json:"wrap"`
	Columns   int    `json:"columns,omitempty"`
	Rows      int    `json:"rows,omitempty"`
}

// A failed decode leaves consumed/trailing lengths and semantic comparisons unknown.
// Tokens retain the decoder's offsets; Payload uses Go's standard JSON base64 encoding.
type StreamAuditSide struct {
	Span           AddressRange `json:"span"`
	SpanSHA256     string       `json:"span_sha256"`
	StreamSHA256   string       `json:"stream_sha256,omitempty"`
	ConsumedBytes  *int         `json:"consumed_bytes"`
	TrailingBytes  *int         `json:"trailing_bytes"`
	Tokens         []TextToken  `json:"tokens,omitempty"`
	GlyphWords     []uint16     `json:"glyph_words,omitempty"`
	GlyphText      string       `json:"glyph_text,omitempty"`
	ArgumentWords  []uint16     `json:"argument_words,omitempty"`
	OpaquePayloads []TextToken  `json:"opaque_payloads,omitempty"`
	Error          string       `json:"error,omitempty"`
}

// Positioned controls include offsets and payloads; sequence equality ignores offsets.
// Argument words exclude opaque payload contents, which are compared separately.
type StreamAuditComparison struct {
	StreamBytesEqual     bool `json:"stream_bytes_equal"`
	GlyphWordsEqual      bool `json:"glyph_words_equal"`
	GlyphTextEqual       bool `json:"glyph_text_equal"`
	ControlTokensEqual   bool `json:"control_tokens_equal"`
	ControlSequenceEqual bool `json:"control_sequence_equal"`
	ArgumentWordsEqual   bool `json:"argument_words_equal"`
	OpaquePayloadsEqual  bool `json:"opaque_payloads_equal"`
}

// StreamAuditStructure counts decoded token lines, not native widths or fit.
// Null means a side/comparison is unknown. Overflow indices count nonempty pages;
// the explicit reference window supplies the headerless line-growth baseline.
type StreamAuditStructure struct {
	LineLimit                    int     `json:"line_limit"`
	ReferencePages               [][]int `json:"reference_pages"`
	ObservedPages                [][]int `json:"observed_pages"`
	ObservedHasHDR               *bool   `json:"observed_has_hdr"`
	ObservedOverLimitPages       []int   `json:"observed_over_limit_pages"`
	HeaderlessLineGrowthAdvisory *bool   `json:"headerless_line_growth_advisory"`
}

type StreamAuditRow struct {
	Structure           *StreamAuditStructure      `json:"structure,omitempty"`
	Reconciliation      *StreamAuditReconciliation `json:"reconciliation,omitempty"`
	ID                  string                     `json:"registry_id"`
	Decoder             string                     `json:"decoder"`
	Status              string                     `json:"status"`
	Reference           StreamAuditSide            `json:"reference"`
	Observed            StreamAuditSide            `json:"observed"`
	SpanBytesEqual      bool                       `json:"span_bytes_equal"`
	FirstDifference     *int                       `json:"first_span_byte_difference"`
	Comparison          *StreamAuditComparison     `json:"comparison"`
	Canonical           *StreamAuditSide           `json:"canonical,omitempty"`
	CanonicalComparison *StreamAuditComparison     `json:"canonical_comparison,omitempty"`
}

type StreamAuditReport struct {
	Operation          string                   `json:"operation"`
	Applied            bool                     `json:"applied"`
	ProfileSHA256      string                   `json:"profile_sha256"`
	Sources            map[string]RegistryInput `json:"sources"`
	Rows               []StreamAuditRow         `json:"rows"`
	Limits             string                   `json:"limits"`
	SentinelAllocation *SentinelAllocation      `json:"sentinel_allocation,omitempty"`
	ObservedReferences *ReferenceReport         `json:"observed_references,omitempty"`
	ReferenceMappings  map[string][]ELFMapping  `json:"reference_mappings,omitempty"`
	ObservedMappings   map[string][]ELFMapping  `json:"observed_mappings,omitempty"`
}
