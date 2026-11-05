package main

import "debug/elf"

type Inspection struct {
	ELFEntry       uint64
	ELFSegments    []elf.ProgHeader
	ELFMappings    map[string][]ELFMapping
	RegisterInfo   *ELFRegisterInfo
	Sentinel       *SentinelAllocation
	Edits          []Edit
	States         []string
	ELF            []byte
	Blob           []byte
	BlobOffset     int64
	Capacity       int64
	Advances       map[uint16]int
	PointerRanges  [][2]uint64
	LandingRanges  [][2]uint64
	MetadataRanges [][2]uint64
}

// ELFRegisterInfo identifies one bounded MIPS metadata record, not runtime $gp.
// Unknown or ambiguous records retain an error rather than choosing a base.
type ELFRegisterInfo struct {
	SectionIndex  *int       `json:"section_index,omitempty"`
	FileRange     *[2]uint64 `json:"file_range,omitempty"`
	GlobalPointer *uint32    `json:"global_pointer"`
	Error         string     `json:"error,omitempty"`
}

// SentinelLayout declares coordinates in one pinned extracted ELF. LoaderVMAs are
// byte-count LUI/ORI then two sector-count instructions; each window site starts
// a LUI/ORI pair. Retail EOF is a declared layout assumption, not discovered truth.
type SentinelLayout struct {
	RetailELFSize int64    `json:"retail_elf_size"`
	LoaderVMAs    []string `json:"loader_vmas"`
	WindowBases   []string `json:"window_bases"`
	WindowSizes   []string `json:"window_sizes"`
}

// SentinelAllocation separates dispatch recognition from physically loaded bytes.
// Words are proved through ordinary PT_LOAD mappings before external mapping exists.
// Neither installed code nor file bytes establish runtime execution or write safety.
type SentinelAllocation struct {
	DispatchRange [2]uint64               `json:"dispatch_range"`
	Loaded        ELFMapping              `json:"loaded"`
	Words         map[string]uint32       `json:"words"`
	WordMappings  map[string][]ELFMapping `json:"word_mappings"`
}

// ELFMapping describes a half-open VMA interval. BSS and unmapped intervals have
// no file range; sentinel_blob is an independently proved external transport with
// no program header. Neither physical mapping proves safe patch placement.
type ELFMapping struct {
	VMA           [2]uint64  `json:"vma_range"`
	Storage       string     `json:"storage"`
	ProgramHeader *int       `json:"program_header,omitempty"`
	FileRange     *[2]uint64 `json:"file_range,omitempty"`
}

type Edit struct {
	ID        string `json:"registry_id"`
	Offset    int64  `json:"offset"`
	Old       []byte `json:"-"`
	New       []byte `json:"-"`
	Operation string `json:"operation"`
}
