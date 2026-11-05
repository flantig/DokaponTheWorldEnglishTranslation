package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
)

var (
	errPNGPixelBudget = errors.New("decoded pixel work budget exhausted")
	errPNGChunkBounds = errors.New("decoded PNG has invalid chunk bounds")
)

type rgbaPNG struct{ *image.NRGBA }

// Opaque keeps the PNG alpha channel required by RGBA previews; pixels stay intact.
func (rgbaPNG) Opaque() bool { return false }

// decodePNG normalizes bounded PNG pixels using the Pillow 12.3 RGBA convention.
// A valid bounded header charges its pixel area even when payload decoding fails;
// invalid headers and refused budgets charge zero. Hidden RGB is preserved.
// Gray16 clamps rather than shifts; tRNS compares after channel conversion.
func decodePNG(data []byte, pixelBudget uint64) (*image.NRGBA, uint64, error) {
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || len(data) > 64<<20 || config.Width < 1 || config.Height < 1 || config.Width > 4096 || config.Height > 4096 || uint64(config.Width)*uint64(config.Height) > 1<<20 {
		return nil, 0, fmt.Errorf("raw PNG is invalid or exceeds pixel bounds")
	}
	area := uint64(config.Width) * uint64(config.Height)
	if area > pixelBudget {
		return nil, 0, errPNGPixelBudget
	}
	candidate, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, area, err
	}
	raster := image.NewNRGBA(image.Rect(0, 0, config.Width, config.Height))
	var transparent *color.NRGBA
	for at := 8; at+12 <= len(data); {
		size := int(binary.BigEndian.Uint32(data[at:]))
		if size > len(data)-at-12 {
			return nil, area, errPNGChunkBounds
		}
		kind, payload := string(data[at+4:at+8]), data[at+8:at+8+size]
		if kind == "IEND" {
			break
		}
		if kind == "tRNS" {
			switch {
			case data[25] == 0 && size == 2:
				gray := uint8(binary.BigEndian.Uint16(payload))
				if data[24] == 1 && gray != 0 {
					gray = 255
				}
				transparent = &color.NRGBA{R: gray, G: gray, B: gray}
			case data[25] == 2 && size == 6:
				transparent = &color.NRGBA{R: uint8(binary.BigEndian.Uint16(payload)), G: uint8(binary.BigEndian.Uint16(payload[2:])), B: uint8(binary.BigEndian.Uint16(payload[4:]))}
			}
		}
		at += 12 + size
	}
	for y := 0; y < config.Height; y++ {
		for x := 0; x < config.Width; x++ {
			pixel := candidate.At(x, y)
			var p color.NRGBA
			switch c := pixel.(type) {
			case color.NRGBA:
				p = c
			case color.NRGBA64:
				p = color.NRGBA{R: uint8(c.R >> 8), G: uint8(c.G >> 8), B: uint8(c.B >> 8), A: uint8(c.A >> 8)}
			default:
				p = color.NRGBAModel.Convert(pixel).(color.NRGBA)
			}
			if data[25] == 0 && data[24] == 16 {
				gray := uint8(min(255, color.NRGBA64Model.Convert(pixel).(color.NRGBA64).R))
				p.R, p.G, p.B = gray, gray, gray
			}
			if data[25] == 0 || data[25] == 2 {
				p.A = 255
				if transparent != nil && p.R == transparent.R && p.G == transparent.G && p.B == transparent.B {
					p.A = 0
				}
			}
			raster.SetNRGBA(x, y, p)
		}
	}
	return raster, area, nil
}
