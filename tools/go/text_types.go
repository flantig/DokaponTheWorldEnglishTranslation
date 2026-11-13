package main

type Boundary struct {
	Word          uint16
	Before, After string
}

type TextToken struct {
	Kind    string
	Word    uint16
	Offset  int
	Payload []byte
}

// LabelRuns splices a reviewed template; character budgets reproduce narrative
// authoring policy; NativeWidth uses measured advances. Neither establishes visual fit.
// SourceAuthoring chooses positional markers, plain prefix state, or ordered source atoms.
type TextEncodeOptions struct {
	Terminated      bool
	ExactControls   bool
	Source          *TextShape
	SourceAuthoring string // Ordered binds every source control occurrence and its opaque payload.
	Columns, Rows   int
	LabelRuns       int
	NativeWidth     int
	Advances        map[uint16]int
	NumericBounds   []*NumericRange
}

// NumericRange bounds one 0x7000 argument in stream order; nested strings stay opaque.
type NumericRange struct {
	Min int32 `json:"min"`
	Max int32 `json:"max"`
}

// TextReadPin declares one exact one-word-per-token interpretation. EndOffset is
// relative bytes, including an explicit zero; roles reuse token coordinates/values.
// It grants no source authoring, native layout or runtime argument semantics.
type TextReadPin struct {
	Words     int         `json:"words"`
	EndOffset *int        `json:"end_offset"`
	SHA256    string      `json:"sha256"`
	Roles     []TextToken `json:"roles"`
}

// Decode uses source grammar; Advances measures native pen movement, not visual ink.
type TextScanOptions struct {
	ReadPin          *TextReadPin // Read-only exact grammar; never an encoding or native-layout policy.
	FixedWords       int          // Decode exactly this many plain glyph words; zero is SPACE, never END.
	Padded           bool         // Known-control slot: one END followed only by zero-filled capacity.
	Terminated       bool
	ExactControls    bool
	Advances         map[uint16]int
	InkBounds        map[uint16][4]int // Optional source-derived half-open bounds relative to the incoming pen.
	Decode           bool
	Glyphs           map[uint16]string
	RequireHDR       bool
	English          *string
	NumericBounds    []*NumericRange
	PositionalLabels bool
}

type TextShape struct {
	glyphText                                           map[uint16]string // Decoded source aliases, retained only for whole-stream no-op identity.
	PositionalLabels                                    bool
	Tokens                                              []TextToken
	ContentStart                                        int
	Kinds                                               []string
	Targets                                             int
	Clusters                                            int
	Readiness                                           string
	TextBeforeFirst, TextAfterLast, TextBetweenClusters bool
	HLCount, HLCleanPairs                               int
	Words                                               []uint16
	Boundaries                                          []Boundary
	Width, Lines                                        int
	LineWidths                                          [][]int
	LineInkBounds                                       [][][4]int
	InkKnown                                            bool
	InkDiagnostic                                       string
	Pages                                               bool
}
