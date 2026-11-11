package main

import "encoding/json"

type Recipe struct {
	Authoring      string               `json:"authoring,omitempty"` // Source policy; existing native and write checks still apply.
	ExpectedHex    string               `json:"expected_hex,omitempty"`
	SourcePointer  string               `json:"source_pointer,omitempty"`
	MaxNewBytes    int                  `json:"max_new_bytes,omitempty"`
	ReadBytes      int                  `json:"read_bytes,omitempty"`
	MaxWidth       int                  `json:"max_width,omitempty"`
	MaxLines       int                  `json:"max_lines,omitempty"`
	LinePageReflow bool                 `json:"line_page_reflow,omitempty"`
	NumericBounds  []*NumericRange      `json:"numeric_bounds,omitempty"`
	EncodedSHA256  string               `json:"encoded_sha256,omitempty"`
	LabelRuns      int                  `json:"label_runs,omitempty"`
	PrefixWords    []string             `json:"prefix_words"`
	Evidence       string               `json:"evidence"`
	Words          []Word               `json:"words,omitempty"`
	Fixups         map[string]WordFixup `json:"fixups,omitempty"`
	Use            string               `json:"use,omitempty"`
}

type Word struct {
	Hex      string `json:"hex"`
	Assembly string `json:"assembly"`
}

// WordFixup inserts a named value's selected bits into a zero field in a template word.
type WordFixup struct {
	Value string `json:"value"`
	Shift uint   `json:"shift"`
	Bits  uint   `json:"bits"`
	LSB   uint   `json:"lsb,omitempty"`
}

type Recipes struct {
	ReferenceFlow   *ReferenceFlowSpec                    `json:"reference_flow,omitempty"`
	RegisterFlow    *RegisterFlowSpec                     `json:"register_flow,omitempty"`
	RegistryInputs  map[string]RegistryInput              `json:"registry_inputs,omitempty"`
	RegistryImport  *RegistryImportSpec                   `json:"registry_import,omitempty"`
	RegistryColumns []string                              `json:"registry_columns,omitempty"`
	AddressRanges   map[string]AddressRange               `json:"address_ranges,omitempty"`
	Sentinel        *SentinelLayout                       `json:"sentinel,omitempty"`
	References      *ReferenceScan                        `json:"references,omitempty"`
	RegistryUpdates map[string]map[string]json.RawMessage `json:"registry_updates,omitempty"`
	Updated         string                                `json:"updated,omitempty"`

	WordingField          string                `json:"wording_field,omitempty"` // Empty uses EN; jp restores canonical original wording in a slot.
	Operation             string                `json:"operation"`
	BaseRecipe            string                `json:"base_recipe,omitempty"`
	BaseSHA256            string                `json:"base_sha256,omitempty"`
	BundlePath            string                `json:"bundle_path,omitempty"`
	BundleSHA256          string                `json:"bundle_sha256,omitempty"`
	OutputSHA256          string                `json:"output_sha256,omitempty"`
	TargetReferenceSHA256 string                `json:"target_reference_sha256,omitempty"`
	Archives              map[string]CMBArchive `json:"archives,omitempty"`
	Files                 map[string]ISOFile    `json:"files,omitempty"`
	Placement             string                `json:"placement,omitempty"`
	PointerState          string                `json:"pointer_state,omitempty"`
	SourceContext         bool                  `json:"source_context,omitempty"`
	SourceSHA256          string                `json:"source_sha256"`
	SourceSize            int64                 `json:"source_size"`
	ISOELFOffset          string                `json:"iso_elf_offset"`
	ELFVMADelta           string                `json:"elf_vma_delta"`
	GlyphmapSHA256        string                `json:"glyphmap_sha256"`
	Evidence              string                `json:"evidence,omitempty"`
	RegistryPatchRef      string                `json:"registry_patch_ref,omitempty"`
	ScopeSHA256           string                `json:"scope_sha256,omitempty"`
	Entries               map[string]Recipe     `json:"entries,omitempty"`
	Stream                *Stream               `json:"stream,omitempty"`
	Layout                *Layout               `json:"layout,omitempty"`
	Growth                *Growth               `json:"growth,omitempty"`
	Values                map[string]string     `json:"values,omitempty"`
	WordBlocks            map[string]Recipe     `json:"word_blocks,omitempty"`
}

// CMBArchive pins the ISO extent and index while members are resolved by name.
type CMBArchive struct {
	SourceISOOffset int64                   `json:"source_iso_offset"`
	Size            int64                   `json:"size"`
	IndexSHA256     string                  `json:"index_sha256"`
	Members         map[string]BundleMember `json:"members"`
}

// BundleMember names one fixed-size replacement in the separately pinned ZIP.
type BundleMember struct {
	Size         int64  `json:"size"`
	SourceSHA256 string `json:"source_sha256"`
	TargetSHA256 string `json:"target_sha256"`
	BundleKey    string `json:"bundle_key"`
}

// ISOFile pins a complete named file after any separate allocation stage.
type ISOFile struct {
	SourceISOOffset int64 `json:"source_iso_offset"`
	BundleMember
}

// Growth describes one reviewed transition; it never permits shrinking or hook installation.
type Growth struct {
	FromSectors uint32       `json:"from_sectors"`
	ToSectors   uint32       `json:"to_sectors"`
	LoaderRange AddressRange `json:"loader_range"`
}

// Layout pins source font, floor-exempt glyph and SPACE facts; bounds default to the JP envelope.
type Layout struct {
	FontTableVMA      string            `json:"font_table_vma"`
	UnflooredGlyphVMA string            `json:"unfloored_glyph_vma"`
	UnflooredGlyph    string            `json:"unfloored_glyph"`
	SpaceWords        map[string]string `json:"space_words"`
	Columns           int               `json:"columns,omitempty"`
	Rows              int               `json:"rows,omitempty"`
}

type AddressRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type Stream struct {
	RetailELFSize    int64             `json:"retail_elf_size"`
	ELFRecordOffset  string            `json:"elf_record_offset"`
	ZeroRecordOffset string            `json:"zero_record_offset"`
	ZeroEnd          string            `json:"zero_end"`
	LoaderVMAs       []string          `json:"loader_vmas"`
	WindowLUIVMAs    []string          `json:"window_lui_vmas"`
	WindowSRLWords   map[string]string `json:"window_srl_words"`
	AllowedPointers  []AddressRange    `json:"allowed_pointers"`
	AllowedLandings  []AddressRange    `json:"allowed_landings"`
}
