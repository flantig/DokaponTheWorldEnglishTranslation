package main

import (
	"fmt"
	"slices"
)

// normalizeReference validates declared data/struct/code coordinates without
// reading words. Inline16 describes four field words, never a pointer target.
// Mapping, consumer ranges, overlaps and target agreement belong
// to callers; minimumVMA is their address floor, not a file-backing guarantee.
func normalizeReference(kind string, site ReferenceSite, minimumVMA uint64) (ReferenceGeometry, error) {
	var geometry ReferenceGeometry
	switch kind {
	case "inline16":
		object, objectErr := number(site.StructVMA)
		offset, offsetErr := number(site.FieldOffset)
		if objectErr != nil || offsetErr != nil || offset != 0 || object > 0xfffffff0 || site.PointerVMA != "" || site.LUIVMA != "" || site.ADDIUVMA != "" || site.Register != "" {
			return geometry, fmt.Errorf("invalid inline16 field coordinates")
		}
		geometry.VMAs = []uint64{object, object + 4, object + 8, object + 12}
	case "pointer_array", "struct_table_field":
		pointer, err := number(site.PointerVMA)
		if err != nil || site.LUIVMA != "" || site.ADDIUVMA != "" || site.Register != "" {
			return geometry, fmt.Errorf("invalid canonical data pointer")
		}
		if kind == "struct_table_field" {
			object, objectErr := number(site.StructVMA)
			offset, offsetErr := number(site.FieldOffset)
			if objectErr != nil || offsetErr != nil || object < minimumVMA || object%4 != 0 || offset%4 != 0 || object+offset != pointer {
				return geometry, fmt.Errorf("invalid canonical struct field coordinates")
			}
		} else if site.StructVMA != "" || site.FieldOffset != "" {
			return geometry, fmt.Errorf("struct coordinates require a struct field")
		}
		geometry.VMAs = []uint64{pointer}
	case "gp_relative":
		addiu, err := number(site.ADDIUVMA)
		reg := slices.Index(mipsRegisters, site.Register)
		if err != nil || reg <= 0 || site.LUIVMA != "" || site.PointerVMA != "" || site.StructVMA != "" || site.FieldOffset != "" {
			return geometry, fmt.Errorf("invalid canonical GP-relative instruction")
		}
		geometry.VMAs, geometry.Register = []uint64{addiu}, uint32(reg)
	case "code_immediate":
		lui, luiErr := number(site.LUIVMA)
		addiu, addiuErr := number(site.ADDIUVMA)
		reg := slices.Index(mipsRegisters, site.Register)
		if luiErr != nil || addiuErr != nil || lui >= addiu || reg <= 0 || site.PointerVMA != "" || site.StructVMA != "" || site.FieldOffset != "" {
			return geometry, fmt.Errorf("invalid canonical code pair")
		}
		geometry.VMAs, geometry.Register = []uint64{lui, addiu}, uint32(reg)
	default:
		return geometry, fmt.Errorf("unsupported canonical reference type")
	}
	alignment := uint64(4)
	if kind == "inline16" {
		alignment = 2
	}
	for _, vma := range geometry.VMAs {
		if vma < minimumVMA || vma%alignment != 0 {
			return ReferenceGeometry{}, fmt.Errorf("invalid canonical reference site")
		}
	}
	return geometry, nil
}

// referenceTarget interprets complete words from normalized geometry. Code pairs
// require exact LUI/ADDIU register bits. A single registered ADDIU needs an
// independently observed ELF GP base; signed low halves wrap modulo 2^32.
// A target says nothing about its backing, stream syntax or runtime reachability.
func referenceTarget(geometry ReferenceGeometry, words []uint32) (uint32, error) {
	if len(words) != len(geometry.VMAs) {
		return 0, fmt.Errorf("incomplete reference words")
	}
	switch len(words) {
	case 1:
		reg := geometry.Register
		if reg == 0 {
			if geometry.GlobalPointer != nil {
				return 0, fmt.Errorf("data pointer has a GP base")
			}
			return words[0], nil
		}
		if reg > 31 || geometry.GlobalPointer == nil || words[0]>>16 != 0x2400|28<<5|reg {
			return 0, fmt.Errorf("GP-relative ADDIU instruction/register/base mismatch")
		}
		return *geometry.GlobalPointer + uint32(int32(int16(words[0]))), nil
	case 2:
		reg := geometry.Register
		if reg == 0 || reg > 31 || geometry.GlobalPointer != nil || words[0]>>16 != 0x3c00|reg || words[1]>>16 != 0x2400|(reg<<5|reg) {
			return 0, fmt.Errorf("code pair instruction/register mismatch")
		}
		return (words[0]&0xffff)<<16 + uint32(int32(int16(words[1]))), nil
	default:
		return 0, fmt.Errorf("invalid reference word count")
	}
}
