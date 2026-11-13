package main

// ReferenceGeometry holds validated word addresses, in pointer or LUI/ADDIU order.
// Register is zero for data. A single registered word also needs the GP value
// independently joined from ELF metadata; normalization never supplies that base.
type ReferenceGeometry struct {
	VMAs          []uint64 `json:"vmas"`
	Register      uint32   `json:"register,omitempty"`
	GlobalPointer *uint32  `json:"global_pointer,omitempty"`
}

// ReferenceScan describes a read-only search. Its matches are candidates, not patch guards.
type ReferenceScan struct {
	AdvanceFloor    int                       `json:"advance_floor,omitempty"`
	SpaceAdvance    int                       `json:"space_advance,omitempty"`
	MissingAdvance  int                       `json:"missing_advance,omitempty"`
	SidecarVMA      string                    `json:"sidecar_vma,omitempty"`
	RawFileRange    AddressRange              `json:"raw_file_range,omitempty"`
	RawPointerRange AddressRange              `json:"raw_pointer_range,omitempty"`
	DataRange       AddressRange              `json:"data_range,omitempty"`
	FileRange       AddressRange              `json:"file_range"`
	PointerMinVMA   string                    `json:"pointer_min_vma"`
	SkipWords       int                       `json:"skip_words"`
	DecodeWords     int                       `json:"decode_words"`
	Queries         map[string]ReferenceQuery `json:"queries"`
}

type ReferenceQuery struct {
	PointerTables    []ReferenceTable  `json:"pointer_tables,omitempty"`
	ExpectedCount    int               `json:"expected_count,omitempty"`
	ExpectedMaxWidth int               `json:"expected_max_width,omitempty"`
	NominalScale     float64           `json:"nominal_scale,omitempty"`
	ScaledLimit      float64           `json:"scaled_limit,omitempty"`
	SourcePool       string            `json:"source_pool,omitempty"`
	Chapter          string            `json:"chapter,omitempty"`
	IDRange          *AddressRange     `json:"id_range,omitempty"`
	ContentRange     AddressRange      `json:"content_range"`
	UnlandedOnly     bool              `json:"unlanded_only,omitempty"`
	Backward         bool              `json:"backward,omitempty"`
	DecodeTarget     bool              `json:"decode_target,omitempty"`
	CheckCollisions  bool              `json:"check_collisions,omitempty"`
	StructRows       []ReferenceTable  `json:"struct_rows,omitempty"`
	OmitIDs          []string          `json:"omit_ids,omitempty"`
	Excluded         map[string]string `json:"excluded,omitempty"`
	Flagged          map[string]string `json:"flagged,omitempty"`
}

type ReferenceTable struct {
	Name   string `json:"name,omitempty"`
	Start  string `json:"start"`
	End    string `json:"end"`
	Stride int    `json:"stride"`
}

// ReferenceSite is the canonical site shape shared by discovery and guarded patching.
type ReferenceSite struct {
	PointerVMA  string `json:"pointer_vma"`
	StructVMA   string `json:"struct_vma,omitempty"`
	FieldOffset string `json:"field_offset,omitempty"`
	LUIVMA      string `json:"lui_vma,omitempty"`
	ADDIUVMA    string `json:"addiu_vma,omitempty"`
	Register    string `json:"reg,omitempty"`
}

// ReferenceCandidate adds evidence without making it part of the patch input contract.
type ReferenceCandidate struct {
	ReferenceSite
	Stride    string `json:"stride,omitempty"`
	Word      string `json:"word,omitempty"`
	LowerWord string `json:"lower_word,omitempty"`
	Target    string `json:"target,omitempty"`
}

type ReferenceRow struct {
	TableName       string                 `json:"table_name,omitempty"`
	Occurrence      *int                   `json:"occurrence,omitempty"`
	BackingSource   string                 `json:"backing_source,omitempty"`
	WordCount       int                    `json:"word_count,omitempty"`
	LineWidths      []int                  `json:"line_widths,omitempty"`
	NominalMaximum  *int                   `json:"nominal_maximum,omitempty"`
	Diagnostics     []string               `json:"diagnostics,omitempty"`
	Flow            *ReferenceFlowRow      `json:"flow,omitempty"`
	ID              string                 `json:"id"`
	Method          string                 `json:"method"`
	RefType         string                 `json:"ref_type"`
	Target          string                 `json:"target,omitempty"`
	ContentStart    string                 `json:"content_start,omitempty"`
	Decoded         string                 `json:"decoded"`
	ContentOK       *bool                  `json:"content_ok"`
	Hybrid          bool                   `json:"hybrid"`
	Note            string                 `json:"note,omitempty"`
	Sites           []ReferenceCandidate   `json:"ref_sites"`
	UnfilteredSites []ReferenceCandidate   `json:"unfiltered_exact_id_sites,omitempty"`
	Collisions      []string               `json:"collision_owner_ids,omitempty"`
	ObservedSites   []ReferenceObservation `json:"observed_sites,omitempty"`
	ObservedTargets []uint32               `json:"observed_targets,omitempty"`
	Divergent       bool                   `json:"divergent,omitempty"`
}

// GPInstruction records arithmetic under an ELF metadata assumption, not live GP.
// RT is a raw opcode field: memory, coprocessor, cache and prefetch forms differ.
// Computed points can be known even for discarded ADDIU results; loaded values cannot.
type GPInstruction struct {
	InstructionWord
	SignedImmediate     int16        `json:"signed_immediate"`
	Kind                string       `json:"kind"`
	ComputedAddress     *uint32      `json:"computed_address"`
	LoadedPointerTarget *uint32      `json:"loaded_pointer_target"`
	MatchedQueries      []string     `json:"matched_queries"`
	SiteMapping         ELFMapping   `json:"site_mapping"`
	TargetMapping       []ELFMapping `json:"target_mapping"`
}

// GPIndex keeps complete source-order supported forms, including unknown metadata.
// Queries select computed points, not memory access extents or retained references.
type GPIndex struct {
	FileRange     AddressRange            `json:"file_range"`
	QueryRanges   map[string]AddressRange `json:"query_ranges"`
	ScannedWords  int                     `json:"scanned_words"`
	Instructions  []GPInstruction         `json:"instructions"`
	MetadataError string                  `json:"metadata_error,omitempty"`
}

type ReferenceReport struct {
	Measurement      string                      `json:"measurement,omitempty"`
	NominalPolicy    map[string]int              `json:"nominal_policy,omitempty"`
	BlobSHA256       string                      `json:"blob_sha256,omitempty"`
	BlobSize         int64                       `json:"blob_size,omitempty"`
	SourcePolicy     map[string]ReferenceFlowRow `json:"source_policy,omitempty"`
	InstructionIndex *InstructionIndex           `json:"instruction_index,omitempty"`
	GPIndex          *GPIndex                    `json:"gp_index,omitempty"`
	RegisterInfo     *ELFRegisterInfo            `json:"register_info,omitempty"`
	ProfileSHA256    string                      `json:"profile_sha256,omitempty"`
	Applied          bool                        `json:"applied"`
	Operation        string                      `json:"operation"`
	SourceSHA256     string                      `json:"source_sha256"`
	RegistrySHA256   string                      `json:"registry_sha256"`
	GlyphmapSHA256   string                      `json:"glyphmap_sha256"`
	Queries          map[string][]ReferenceRow   `json:"queries"`
	Summaries        map[string]ReferenceSummary `json:"summaries"`
	Limits           string                      `json:"limits"`
}

type ReferenceSummary struct {
	NominalMaximum    *int           `json:"nominal_maximum,omitempty"`
	NominalScaled     *float64       `json:"nominal_scaled,omitempty"`
	NominalPolicyOK   *bool          `json:"nominal_policy_ok,omitempty"`
	Diagnostics       []string       `json:"diagnostics,omitempty"`
	ObservedSites     int            `json:"observed_sites,omitempty"`
	FailedSites       int            `json:"failed_sites,omitempty"`
	DivergentRows     int            `json:"divergent_rows,omitempty"`
	Total             int            `json:"total"`
	Resolved          int            `json:"resolved"`
	Unresolved        int            `json:"unresolved"`
	ContentMismatches int            `json:"content_mismatches"`
	Hybrids           int            `json:"hybrids"`
	MultiSite         int            `json:"multi_site"`
	CollisionRows     int            `json:"collision_rows"`
	ByType            map[string]int `json:"by_type"`
}

// ReferenceObservation retains each declared site, even when targets repeat or
// words cannot be interpreted. Null words/target are unknown; mappings describe
// exact word spans or a single target byte, never a whole stream or liveness.
// reference_inline16 observes four field words; its target stays null because
// inline glyphs encode no pointer. The audit separately maps both full fields.
type ReferenceObservation struct {
	Ordinal       int               `json:"ordinal"`
	Site          ReferenceSite     `json:"site"`
	Geometry      ReferenceGeometry `json:"geometry"`
	Words         []*uint32         `json:"words"`
	WordMappings  [][]ELFMapping    `json:"word_mappings"`
	Target        *uint32           `json:"target"`
	TargetMapping []ELFMapping      `json:"target_mapping"`
	Error         string            `json:"error,omitempty"`
}
