package main

// InstructionWord shares raw coordinates between finite indexes, without proving code.
type InstructionWord struct {
	FileOffset uint64 `json:"file_offset"`
	VMA        uint64 `json:"vma"`
	Word       uint32 `json:"word"`
	Opcode     uint32 `json:"opcode"`
	RS         uint32 `json:"rs"`
	RT         uint32 `json:"rt"`
}

// InstructionIndex retains every selected word, including unsupported forms.
// Local transfer facts stay separate from optional, entry-scoped graph queries.
type InstructionIndex struct {
	RegisterFlow *RegisterFlowReport      `json:"register_flow,omitempty"`
	FileRange    AddressRange             `json:"file_range"`
	ScannedWords int                      `json:"scanned_words"`
	Instructions []InstructionObservation `json:"instructions"`
}

type InstructionObservation struct {
	InstructionWord
	transfer    *instructionTransfer
	memory      *instructionMemory
	RD          uint32              `json:"rd"`
	Operands    InstructionOperands `json:"operands"`
	Control     *InstructionControl `json:"control"`
	NextVMA     *uint32             `json:"next_vma"`
	NextInScan  *bool               `json:"next_in_scan"`
	SiteMapping ELFMapping          `json:"site_mapping"`
}

// Internal facts are decoded once; expanding an analysis adds no public index fields.
type instructionTransfer struct {
	kind                string
	source, destination uint32
	displacement        int32
}

type instructionMemory struct {
	kind, bank   string
	base, value  uint32
	width        int
	displacement int32
	merge        bool
}

// InstructionOperands describes finite operand roles on normal completion.
// Destination sets do not prove a complete128-bit overwrite. Preservation lists
// model conditional/merge dependencies, not every preserved architectural lane.
// Unsupported forms keep GPR sets null rather than claiming no effects.
type InstructionOperands struct {
	Status               string                   `json:"status"`
	GPRReads             []uint32                 `json:"gpr_reads"`
	GPRMayWrite          []uint32                 `json:"gpr_may_write"`
	GPRMustWrite         []uint32                 `json:"gpr_must_write_on_normal_completion"`
	IncomingPreservation []uint32                 `json:"incoming_preservation_dependencies"`
	OtherBanks           []InstructionBankOperand `json:"other_operand_banks"`
	OtherEffects         []string                 `json:"other_effects_or_dependencies"`
}

// InstructionBankOperand keeps non-GPR indexes separate; conditions have no index.
type InstructionBankOperand struct {
	Role  string  `json:"role"`
	Bank  string  `json:"bank"`
	Index *uint32 `json:"index"`
}

// InstructionControl retains numeric local paths even when delay context fails.
// A link value is not a return edge. Indirect and exception destinations stay unknown.
type InstructionControl struct {
	Status        string            `json:"status"`
	Kind          string            `json:"kind"`
	Target        *uint32           `json:"target"`
	Condition     *string           `json:"condition"`
	Likely        bool              `json:"likely"`
	LinkRegister  *uint32           `json:"link_register"`
	LinkValue     *uint32           `json:"link_value"`
	DelayVMA      *uint32           `json:"delay_vma"`
	DelayError    string            `json:"delay_error,omitempty"`
	PossiblePaths []InstructionPath `json:"possible_paths"`
}

type InstructionPath struct {
	ConditionTaken bool   `json:"condition_taken"`
	ExecuteDelay   bool   `json:"execute_delay"`
	NextAfterDelay uint32 `json:"next_after_delay"`
	NextInScan     bool   `json:"next_in_scan"`
}
