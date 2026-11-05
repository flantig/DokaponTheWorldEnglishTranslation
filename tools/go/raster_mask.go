package main

import (
	"fmt"
	"image"
	"maps"
	"math"
	"slices"
)

const (
	maskLuminance = iota
	maskSaturation
	maskRed
	maskGreen
	maskBlue
	maskAlpha
	maskRedBlue
	maskBlueRed
	maskRedGreen
	maskGreenBlue
	maskPropertyCount
)

var rasterMaskProperties = map[string]int{
	"luminance": maskLuminance, "saturation": maskSaturation,
	"red": maskRed, "green": maskGreen, "blue": maskBlue, "alpha": maskAlpha,
	"red-blue": maskRedBlue, "blue-red": maskBlueRed, "red-green": maskRedGreen,
	"green-blue": maskGreenBlue,
}

// selectRaster constructs a crop-local mask without changing pixels or caller masks.
// Any is OR-of-AND; fixed topology reads an immutable core for each derivation.
// Returned work is a charged upper bound, checked before pixel work, not a visit count.
func selectRaster(raster *image.NRGBA, spec RasterFootprint, maxWork int64) ([]bool, int64, error) {
	if raster == nil || raster.Rect.Dx() < 1 || raster.Rect.Dy() < 1 || raster.Rect.Dx() > 4096 || raster.Rect.Dy() > 4096 || raster.Rect.Dx()*raster.Rect.Dy() > 1<<20 || len(spec.Rect) != 4 {
		return nil, 0, fmt.Errorf("raster selection requires bounded pixels and a rectangle")
	}
	x, y, w, h := spec.Rect[0], spec.Rect[1], spec.Rect[2], spec.Rect[3]
	if x < 0 || y < 0 || w < 1 || h < 1 || w > raster.Rect.Dx()-x || h > raster.Rect.Dy()-y {
		return nil, 0, fmt.Errorf("raster selection rectangle exceeds pixels")
	}
	sample := spec.SampleRect
	if sample == nil {
		sample = spec.Rect
	}
	if len(sample) != 4 || sample[0] < x || sample[1] < y || sample[2] < 1 || sample[3] < 1 || sample[2] > x+w-sample[0] || sample[3] > y+h-sample[1] {
		return nil, 0, fmt.Errorf("sampling rectangle must be inside the topology rectangle")
	}
	var componentSeeds []int
	if components := spec.Components; components != nil {
		if components.Connectivity != 4 && components.Connectivity != 8 {
			return nil, 0, fmt.Errorf("component connectivity requires four or eight neighbors")
		}
		if components.Seeds != nil {
			if len(*components.Seeds) > maxRasterSelections {
				return nil, 0, fmt.Errorf("component seeds exceed bounded count")
			}
			// A present empty list must remain nonnil: it selects no components.
			componentSeeds = make([]int, 0, len(*components.Seeds))
			for _, seed := range *components.Seeds {
				if len(seed) != 2 || seed[0] < sample[0] || seed[1] < sample[1] || seed[0]-sample[0] >= sample[2] || seed[1]-sample[1] >= sample[3] {
					return nil, 0, fmt.Errorf("component seed must be inside the sampling rectangle")
				}
				componentSeeds = append(componentSeeds, (seed[1]-y)*w+seed[0]-x)
			}
		}
	}
	switch spec.Fill {
	case "", "none", "holes":
	case "core":
		if spec.Core == nil {
			return nil, 0, fmt.Errorf("core filling requires an explicit core")
		}
	default:
		return nil, 0, fmt.Errorf("unknown footprint fill %q", spec.Fill)
	}
	if spec.Core == nil && spec.CoreGrow != nil {
		return nil, 0, fmt.Errorf("core growth requires an explicit core")
	}
	if len(spec.Exclude) > 64 || math.IsNaN(spec.MinimumSize) || math.IsInf(spec.MinimumSize, 0) {
		return nil, 0, fmt.Errorf("footprint exclusions or component size exceed bounds")
	}
	bounds := image.Rect(0, 0, raster.Rect.Dx(), raster.Rect.Dy())
	geometry := spec.Exclude
	if spec.Clip != nil {
		geometry = append(slices.Clone(geometry), spec.Clip)
	}
	for _, r := range geometry {
		if len(r) != 4 || r[0] < 0 || r[1] < 0 || r[2] < 1 || r[3] < 1 || r[2] > bounds.Dx()-r[0] || r[3] > bounds.Dy()-r[1] {
			return nil, 0, fmt.Errorf("footprint clip or exclusion exceeds canvas")
		}
	}
	sets := [3][][]RasterSelection{spec.Any, nil, nil}
	if spec.Core != nil {
		sets[1] = *spec.Core
	}
	if spec.Components != nil && spec.Components.Reject != nil {
		sets[2] = *spec.Components.Reject
	}
	weight := int64(0)
	for _, groups := range sets {
		if len(groups) > maxRasterSelections {
			return nil, 0, fmt.Errorf("footprint exceeds bounded OR groups")
		}
		for _, group := range groups {
			if len(group) > maxRasterSelections+1 {
				return nil, 0, fmt.Errorf("footprint exceeds bounded AND clauses")
			}
			weight++
			for _, selection := range group {
				weight += int64(12 + len(selection.Above) + len(selection.Below))
			}
		}
	}
	if spec.Close != 0 || spec.Fill == "holes" || spec.Fill == "core" || spec.Core != nil || spec.MinimumSize != 0 || spec.Grow != 0 {
		weight += 64
	}
	if spec.Components != nil {
		weight += 80 // One eight-neighbor component pass plus bounded seed preparation.
	}
	if spec.Erode != 0 {
		weight += 16
	}
	if len(geometry) > 0 {
		weight += int64(1 + len(geometry))
	}
	charged := int64(w) * int64(h) * max(int64(1), weight)
	if charged > maxWork {
		return nil, 0, fmt.Errorf("footprint exceeds bounded pixel work")
	}
	masks := [3][]bool{}
	origin := raster.Rect.Min.Add(image.Pt(x, y))
	for set, groups := range sets {
		if set == 1 && spec.Core == nil {
			continue
		}
		if set == 2 && (spec.Components == nil || spec.Components.Reject == nil) {
			continue
		}
		masks[set] = make([]bool, w*h)
		for _, selections := range groups {
			checks := make([]rasterScalarCheck, 0, len(selections)*3)
			for _, selection := range selections {
				for _, bound := range []struct {
					property  int
					below     bool
					threshold *float64
				}{
					{maskLuminance, true, selection.LuminanceBelow},
					{maskLuminance, false, selection.LuminanceAbove},
					{maskSaturation, true, selection.SaturationBelow},
				} {
					if bound.threshold == nil {
						continue
					}
					if math.IsNaN(*bound.threshold) || math.IsInf(*bound.threshold, 0) {
						return nil, 0, fmt.Errorf("reconstruction selection threshold must be finite")
					}
					checks = append(checks, rasterScalarCheck{bound.property, bound.below, *bound.threshold})
				}
				for _, direction := range [2]struct {
					bounds map[string]float64
					below  bool
				}{{selection.Above, false}, {selection.Below, true}} {
					if len(direction.bounds) > len(rasterMaskProperties) {
						return nil, 0, fmt.Errorf("raster selection exceeds finite scalar properties")
					}
					for _, name := range slices.Sorted(maps.Keys(direction.bounds)) {
						property, known := rasterMaskProperties[name]
						if !known {
							return nil, 0, fmt.Errorf("unknown raster scalar property %q", name)
						}
						threshold := direction.bounds[name]
						if math.IsNaN(threshold) || math.IsInf(threshold, 0) {
							return nil, 0, fmt.Errorf("raster scalar threshold must be finite")
						}
						checks = append(checks, rasterScalarCheck{property, direction.below, threshold})
					}
				}
				for _, reference := range [][]int{selection.Near, selection.NotNear} {
					if reference == nil {
						continue
					}
					if len(reference) != 3 && len(reference) != 4 {
						return nil, 0, fmt.Errorf("reconstruction color selection requires RGB or RGBA")
					}
					for _, value := range reference {
						if value < 0 || value > 255 {
							return nil, 0, fmt.Errorf("reconstruction selection color outside0..255")
						}
					}
				}
			}
			for row := 0; row < h; row++ {
				for column := 0; column < w; column++ {
					if x+column < sample[0] || y+row < sample[1] || x+column-sample[0] >= sample[2] || y+row-sample[1] >= sample[3] {
						continue
					}
					point := origin.Add(image.Pt(column, row))
					pixel := raster.NRGBAAt(point.X, point.Y)
					lum := (299*int(pixel.R) + 587*int(pixel.G) + 114*int(pixel.B)) / 1000
					saturation := max(pixel.R, pixel.G, pixel.B) - min(pixel.R, pixel.G, pixel.B)
					values := [maskPropertyCount]int{
						maskLuminance: lum, maskSaturation: int(saturation),
						maskRed: int(pixel.R), maskGreen: int(pixel.G), maskBlue: int(pixel.B), maskAlpha: int(pixel.A),
						maskRedBlue: int(pixel.R) - int(pixel.B), maskBlueRed: int(pixel.B) - int(pixel.R), maskRedGreen: int(pixel.R) - int(pixel.G),
						maskGreenBlue: int(pixel.G) - int(pixel.B),
					}
					selected := true
					for _, check := range checks {
						value := float64(values[check.property])
						if check.below {
							selected = value < check.threshold
						} else {
							selected = value > check.threshold
						}
						if !selected {
							break
						}
					}
					for _, selection := range selections {
						if !selected {
							break
						}
						for _, match := range [2]struct {
							rgb     []int
							exclude bool
						}{{selection.Near, false}, {selection.NotNear, true}} {
							if match.rgb == nil {
								continue
							}
							distance := 0
							for channel, value := range [3]uint8{pixel.R, pixel.G, pixel.B} {
								delta := int(value) - match.rgb[channel]
								distance = max(distance, delta, -delta)
							}
							if match.exclude {
								selected = selected && distance > selection.Tolerance
							} else {
								selected = selected && distance <= selection.Tolerance
							}
						}
						if !selected {
							break
						}
					}
					if selected {
						at := row*w + column
						masks[set][at] = true
					}
				}
			}

		}
	}
	mask, core := masks[0], masks[1]
	var err error
	if spec.Close != 0 {
		mask, err = transformRasterMask(mask, w, RasterMaskTransform{Kind: "close", Iterations: spec.Close})
		if err != nil {
			return nil, 0, err
		}
	}
	switch spec.Fill {
	case "holes":
		mask, err = transformRasterMask(mask, w, RasterMaskTransform{Kind: "fill_holes"})
		if err != nil {
			return nil, 0, err
		}
	case "core":
		filled, err := transformRasterMask(core, w, RasterMaskTransform{Kind: "fill_holes"})
		if err != nil {
			return nil, 0, err
		}
		for at, selected := range filled {
			mask[at] = mask[at] || selected
		}
	}
	if spec.Core != nil {
		growth := 4
		if spec.CoreGrow != nil {
			growth = *spec.CoreGrow
		}
		grown, err := transformRasterMask(core, w, RasterMaskTransform{Kind: "dilate", Iterations: growth})
		if err != nil {
			return nil, 0, err
		}
		for at, selected := range grown {
			mask[at] = mask[at] && selected
		}
	}
	if spec.MinimumSize != 0 || spec.Components != nil {
		filter := RasterMaskTransform{Kind: "minimum", MinimumSize: spec.MinimumSize}
		if spec.Components != nil {
			filter.Kind = "components"
			filter.Connectivity = spec.Components.Connectivity
			filter.Seeds = componentSeeds
			filter.Reject = masks[2]
			filter.BackgroundSeed = spec.Components.BackgroundSeed
		}
		mask, err = transformRasterMask(mask, w, filter)
		if err != nil {
			return nil, 0, err
		}
	}
	if spec.Erode != 0 {
		mask, err = transformRasterMask(mask, w, RasterMaskTransform{Kind: "erode", Iterations: spec.Erode})
		if err != nil {
			return nil, 0, err
		}
	}
	if spec.Grow != 0 {
		mask, err = transformRasterMask(mask, w, RasterMaskTransform{Kind: "dilate", Iterations: spec.Grow})
		if err != nil {
			return nil, 0, err
		}
	}
	if len(geometry) == 0 {
		return mask, charged, nil
	}
	for at, selected := range mask {
		if !selected {
			continue
		}
		point := image.Pt(x+at%w, y+at/w)
		if spec.Clip != nil {
			r := spec.Clip
			if !point.In(image.Rect(r[0], r[1], r[0]+r[2], r[1]+r[3])) {
				mask[at] = false
				continue
			}
		}
		for _, r := range spec.Exclude {
			if point.In(image.Rect(r[0], r[1], r[0]+r[2], r[1]+r[3])) {
				mask[at] = false
				break
			}
		}
	}
	return mask, charged, nil
}

// transformRasterMask returns an owned binary mask; all input bits remain immutable.
// Component filtering shares one traversal for size, seed membership and tag veto.
// Component connectivity is explicit; morphology and hole filling stay four-connected.
// Morphology stops at saturation; nonpositive iterations mean until stable.
// The crop exterior is false, including during erosion and hole classification.
func transformRasterMask(mask []bool, width int, spec RasterMaskTransform) ([]bool, error) {
	if width < 1 || width > 4096 || len(mask) < 1 || len(mask) > 1<<20 || len(mask)%width != 0 || len(mask)/width > 4096 {
		return nil, fmt.Errorf("mask transform requires bounded complete rows")
	}
	if spec.Kind != "components" && (spec.Connectivity != 0 || spec.Seeds != nil || spec.Reject != nil || spec.BackgroundSeed != "") {
		return nil, fmt.Errorf("component criteria require the components transform")
	}
	switch spec.Kind {
	case "dilate", "erode", "close":
		if spec.MinimumSize != 0 {
			return nil, fmt.Errorf("mask morphology takes no component size")
		}
	case "fill_holes":
		if spec.Iterations != 0 || spec.MinimumSize != 0 {
			return nil, fmt.Errorf("mask hole filling takes no iteration or component count")
		}
	case "minimum", "components":
		if spec.Iterations != 0 || math.IsNaN(spec.MinimumSize) || math.IsInf(spec.MinimumSize, 0) {
			return nil, fmt.Errorf("mask component filtering requires a finite size without iterations")
		}
	default:
		return nil, fmt.Errorf("unknown mask transform %q", spec.Kind)
	}
	var seeded []bool
	backgroundSeed := false
	if spec.Kind == "components" {
		if spec.Connectivity != 4 && spec.Connectivity != 8 || len(spec.Seeds) > maxRasterSelections || spec.Reject != nil && len(spec.Reject) != len(mask) {
			return nil, fmt.Errorf("invalid component connectivity, seed count or rejection mask")
		}
		switch spec.BackgroundSeed {
		case "":
		case "label-zero":
			if spec.Seeds == nil || spec.MinimumSize != 0 || spec.Reject != nil {
				return nil, fmt.Errorf("label-zero selection requires explicit seeds without size or rejection criteria")
			}
		default:
			return nil, fmt.Errorf("unknown background seed policy %q", spec.BackgroundSeed)
		}
		if spec.Seeds != nil {
			seeded = make([]bool, len(mask))
			for _, seed := range spec.Seeds {
				if seed < 0 || seed >= len(mask) {
					return nil, fmt.Errorf("component seed exceeds mask")
				}
				if !mask[seed] && spec.BackgroundSeed != "label-zero" {
					return nil, fmt.Errorf("component seed must select a foreground pixel")
				}
				backgroundSeed = backgroundSeed || !mask[seed]
				seeded[seed] = true
			}
		}
	}
	if spec.Kind == "close" {
		grown, err := transformRasterMask(mask, width, RasterMaskTransform{Kind: "dilate", Iterations: spec.Iterations})
		if err != nil {
			return nil, err
		}
		return transformRasterMask(grown, width, RasterMaskTransform{Kind: "erode", Iterations: spec.Iterations})
	}
	height := len(mask) / width
	steps := [4]image.Point{{X: -1}, {X: 1}, {Y: -1}, {Y: 1}}
	result := slices.Clone(mask)
	queue := make([]int, 0, len(mask))
	if spec.Kind == "minimum" || spec.Kind == "components" {
		neighbors := steps[:]
		if spec.Connectivity == 8 {
			neighbors = append(neighbors, image.Pt(-1, -1), image.Pt(1, -1), image.Pt(-1, 1), image.Pt(1, 1))
		}
		seen := make([]bool, len(mask))
		for seed, selected := range mask {
			if !selected || seen[seed] {
				continue
			}
			queue = append(queue[:0], seed)
			seen[seed] = true
			containsSeed, rejected := seeded == nil, false
			for head := 0; head < len(queue); head++ {
				at := queue[head]
				if seeded != nil && seeded[at] {
					containsSeed = true
				}
				if spec.Reject != nil && spec.Reject[at] {
					rejected = true
				}
				point := image.Pt(at%width, at/width)
				for _, step := range neighbors {
					next := point.Add(step)
					if next.X < 0 || next.X >= width || next.Y < 0 || next.Y >= height {
						continue
					}
					at := next.Y*width + next.X
					if mask[at] && !seen[at] {
						seen[at] = true
						queue = append(queue, at)
					}
				}
			}
			if float64(len(queue)) < spec.MinimumSize || !containsSeed || rejected {
				for _, at := range queue {
					result[at] = false
				}
			}
		}
		if backgroundSeed {
			// Label zero aggregates immutable input background, even across disconnected regions.
			for at, selected := range mask {
				if !selected {
					result[at] = true
				}
			}
		}
		return result, nil
	}
	for at, selected := range mask {
		x, y := at%width, at/width
		switch spec.Kind {
		case "dilate":
			if selected {
				queue = append(queue, at)
			}
		case "erode":
			if !selected {
				continue
			}
			boundary := x == 0 || y == 0 || x == width-1 || y == height-1
			if !boundary {
				boundary = !mask[at-1] || !mask[at+1] || !mask[at-width] || !mask[at+width]
			}
			if boundary {
				result[at] = false
				queue = append(queue, at)
			}
		case "fill_holes":
			result[at] = true
			if !selected && (x == 0 || y == 0 || x == width-1 || y == height-1) {
				result[at] = false
				queue = append(queue, at)
			}
		}
	}
	start, end, ring := 0, len(queue), 0
	if spec.Kind == "erode" {
		ring = 1
	} // The initial frontier is the first removed layer.
	for ; start < end; ring++ {
		if spec.Kind != "fill_holes" && spec.Iterations > 0 && ring >= spec.Iterations {
			break
		}
		for ; start < end; start++ {
			point := image.Pt(queue[start]%width, queue[start]/width)
			for _, step := range steps {
				next := point.Add(step)
				if next.X < 0 || next.X >= width || next.Y < 0 || next.Y >= height {
					continue
				}
				at := next.Y*width + next.X
				switch spec.Kind {
				case "dilate":
					if result[at] {
						continue
					}
					result[at] = true
				case "erode":
					if !result[at] {
						continue
					}
					result[at] = false
				case "fill_holes":
					if mask[at] || !result[at] {
						continue
					}
					result[at] = false
				}
				queue = append(queue, at)
			}
		}
		end = len(queue)
	}
	return result, nil
}
