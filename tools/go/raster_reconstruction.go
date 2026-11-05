package main

import (
	"fmt"
	"image"
	"image/color"
	"math"
	"slices"
)

// reconstructRaster applies one erase to a caller-owned working copy.
// Selection and donors read current straight RGBA; growth uses four neighbors.
// Donors are the complement of the final hole inside the operation's crop.
// An empty selection bypasses method/fill checks, and donorless scanlines stay unchanged.
// The caller discards the working copy on error and owns publication/permission geometry.
func reconstructRaster(canvas *image.NRGBA, allow *image.Alpha, operation RasterErase) error {
	if canvas == nil || allow == nil || canvas.Rect != allow.Rect || canvas.Rect.Dx() < 1 || canvas.Rect.Dy() < 1 || canvas.Rect.Dx() > 4096 || canvas.Rect.Dy() > 4096 || canvas.Rect.Dx()*canvas.Rect.Dy() > 1<<20 || len(operation.Rect) != 4 {
		return fmt.Errorf("reconstruction requires bounded working pixels, an exact allow mask and a rectangle")
	}
	r := operation.Rect
	x, y, w, h := r[0], r[1], r[2], r[3]
	if x < 0 || y < 0 || w < 1 || h < 1 || w > canvas.Rect.Dx()-x || h > canvas.Rect.Dy()-y {
		return fmt.Errorf("reconstruction rectangle exceeds canvas: %s", operation.ID)
	}
	if len(operation.All) > maxRasterSelections {
		return fmt.Errorf("reconstruction exceeds bounded selection clauses")
	}
	hole, _, err := selectRaster(canvas, RasterFootprint{Rect: r, Any: [][]RasterSelection{append([]RasterSelection{operation.RasterSelection}, operation.All...)}}, math.MaxInt64)
	if err != nil {
		return err
	}
	origin := canvas.Rect.Min.Add(image.Pt(x, y))
	// Select current pixels inside permission before growth; clip again afterward.
	for at, selected := range hole {
		if selected && allow.AlphaAt(origin.X+at%w, origin.Y+at/w).A == 0 {
			hole[at] = false
		}
	}
	if !slices.Contains(hole, true) {
		return nil
	}
	if operation.Grow > 0 {
		hole, err = transformRasterMask(hole, w, RasterMaskTransform{Kind: "dilate", Iterations: operation.Grow})
		if err != nil {
			return err
		}
	}
	for at, selected := range hole {
		if selected && allow.AlphaAt(origin.X+at%w, origin.Y+at/w).A == 0 {
			hole[at] = false
		}
	}
	switch operation.Method {
	case "", "flat", "clear":
		var fill color.NRGBA
		if operation.Method != "clear" {
			if len(operation.Fill) != 3 && len(operation.Fill) != 4 {
				return fmt.Errorf("flat reconstruction requires RGB or RGBA: %s", operation.ID)
			}
			for _, value := range operation.Fill {
				if value < 0 || value > 255 {
					return fmt.Errorf("reconstruction color outside0..255")
				}
			}
			fill = color.NRGBA{uint8(operation.Fill[0]), uint8(operation.Fill[1]), uint8(operation.Fill[2]), 255}
			if len(operation.Fill) == 4 {
				fill.A = uint8(operation.Fill[3])
			}
		}
		for at, selected := range hole {
			if selected {
				canvas.SetNRGBA(origin.X+at%w, origin.Y+at/w, fill)
			}
		}
	case "rows", "cols":
		lines, length, lineStride, pointStride := h, w, w, 1
		if operation.Method == "cols" {
			lines, length, lineStride, pointStride = w, h, 1, w
		}
		known := make([]int, 0, length)
		pixels := make([]color.NRGBA, 0, length)
		for line := 0; line < lines; line++ {
			known, pixels = known[:0], pixels[:0]
			for along := 0; along < length; along++ {
				at := line*lineStride + along*pointStride
				if !hole[at] {
					known = append(known, along)
					pixels = append(pixels, canvas.NRGBAAt(origin.X+at%w, origin.Y+at/w))
				}
			}
			if len(known) == 0 {
				continue
			}
			upper := 0
			for along := 0; along < length; along++ {
				at := line*lineStride + along*pointStride
				if !hole[at] {
					continue
				}
				for upper < len(known) && known[upper] < along {
					upper++
				}
				var pixel color.NRGBA
				switch {
				case upper == 0:
					pixel = pixels[0]
				case upper == len(known):
					pixel = pixels[len(pixels)-1]
				default:
					lo, hi := pixels[upper-1], pixels[upper]
					var rgba [4]uint8
					for channel, value := range [4]uint8{lo.R, lo.G, lo.B, lo.A} {
						target := [4]uint8{hi.R, hi.G, hi.B, hi.A}
						slope := float64(int(target[channel])-int(value)) / float64(known[upper]-known[upper-1])
						// Explicit float64 rounding keeps NumPy's multiply/add order, without fusion.
						interpolated := float64(slope*float64(along-known[upper-1])) + float64(value)
						rgba[channel] = uint8(math.RoundToEven(interpolated))
					}
					pixel = color.NRGBA{rgba[0], rgba[1], rgba[2], rgba[3]}
				}
				canvas.SetNRGBA(origin.X+at%w, origin.Y+at/w, pixel)
			}
		}
	default:
		return fmt.Errorf("unknown reconstruction method %q", operation.Method)
	}
	return nil
}
