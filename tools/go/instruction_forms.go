package main

// instructionAddressForm is shared by GP-address and general operand indexes.
// It is a finite R5900 address-form table, not a complete instruction decoder.
type instructionAddressForm struct {
	Kind       string
	ValueBank  string
	PreserveRT bool
}

var instructionAddressForms = map[uint32]instructionAddressForm{
	0x09: {Kind: "constructed_address", ValueBank: "GPR"},
	0x1a: {Kind: "load", ValueBank: "GPR", PreserveRT: true},
	0x1b: {Kind: "load", ValueBank: "GPR", PreserveRT: true},
	0x1e: {Kind: "load", ValueBank: "GPR"},
	0x20: {Kind: "load", ValueBank: "GPR"},
	0x21: {Kind: "load", ValueBank: "GPR"},
	0x22: {Kind: "load", ValueBank: "GPR", PreserveRT: true},
	0x23: {Kind: "load", ValueBank: "GPR"},
	0x24: {Kind: "load", ValueBank: "GPR"},
	0x25: {Kind: "load", ValueBank: "GPR"},
	0x26: {Kind: "load", ValueBank: "GPR", PreserveRT: true},
	0x27: {Kind: "load", ValueBank: "GPR"},
	0x31: {Kind: "load", ValueBank: "FPR"},
	0x36: {Kind: "load", ValueBank: "COP2_vector"},
	0x37: {Kind: "load", ValueBank: "GPR"},
	0x1f: {Kind: "store", ValueBank: "GPR"},
	0x28: {Kind: "store", ValueBank: "GPR"},
	0x29: {Kind: "store", ValueBank: "GPR"},
	0x2a: {Kind: "store", ValueBank: "GPR"},
	0x2b: {Kind: "store", ValueBank: "GPR"},
	0x2c: {Kind: "store", ValueBank: "GPR"},
	0x2d: {Kind: "store", ValueBank: "GPR"},
	0x2e: {Kind: "store", ValueBank: "GPR"},
	0x39: {Kind: "store", ValueBank: "FPR"},
	0x3e: {Kind: "store", ValueBank: "COP2_vector"},
	0x3f: {Kind: "store", ValueBank: "GPR"},
	0x2f: {Kind: "cache", ValueBank: "non_register_field"},
	0x33: {Kind: "prefetch", ValueBank: "non_register_field"},
}
