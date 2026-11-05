package main

import (
	"fmt"
	"image"
	"image/color"
	"math"
	"slices"
)

// generatePalette normalizes a whole candidate and assigns logical PSMT8 indices.
// Exact refuses more than256 colors. Quantize uses unique-color variance, weighted
// median cuts and exactly8 weighted Lloyd updates; assignments precede ties-even
// centroid rounding. Empty clusters and rounded duplicate entries retain their slots.
func generatePalette(candidate image.Image, policy string) (*image.NRGBA, []color.NRGBA, map[color.NRGBA]byte, error) {
	bounds := candidate.Bounds()
	normalized := image.NewNRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	counts := make(map[color.NRGBA]int)
	for y := 0; y < bounds.Dy(); y++ {
		for x := 0; x < bounds.Dx(); x++ {
			pixel := color.NRGBAModel.Convert(candidate.At(x+bounds.Min.X, y+bounds.Min.Y)).(color.NRGBA)
			pixel.A = uint8(min(255, 2*((int(pixel.A)+1)/2)))
			if pixel.A == 0 {
				pixel.R, pixel.G, pixel.B = 0, 0, 0
			}
			normalized.SetNRGBA(x, y, pixel)
			counts[pixel]++
			if policy == "exact" && len(counts) > 256 {
				return nil, nil, nil, fmt.Errorf("exact palette exceeds256 normalized colors")
			}
		}
	}
	// Packed RGBA sorts like the reference tuples; transparency is all zero.
	colors := make([]uint32, 0, len(counts))
	for pixel := range counts {
		colors = append(colors, uint32(pixel.R)<<24|uint32(pixel.G)<<16|uint32(pixel.B)<<8|uint32(pixel.A))
	}
	slices.Sort(colors)
	palette := make([]color.NRGBA, 256)
	indices := make(map[color.NRGBA]byte, len(colors))
	if len(colors) <= 256 {
		for index, value := range colors {
			pixel := color.NRGBA{uint8(value >> 24), uint8(value >> 16), uint8(value >> 8), uint8(value)}
			palette[index], indices[pixel] = pixel, byte(index)
		}
		return normalized, palette, indices, nil
	}

	// Nontransparent inputs have alpha>=2, so only the reserved entry sorts first.
	first := 0
	if colors[0] == 0 {
		first = 1
		indices[color.NRGBA{}] = 0
	}
	colors = colors[first:]
	points := make([][4]float64, len(colors))
	weights := make([]float64, len(colors))
	members := make([]int, len(colors))
	for i, value := range colors {
		pixel := color.NRGBA{uint8(value >> 24), uint8(value >> 16), uint8(value >> 8), uint8(value)}
		points[i] = [4]float64{float64(pixel.R), float64(pixel.G), float64(pixel.B), float64(pixel.A)}
		weights[i], members[i] = float64(counts[pixel]), i
	}
	type paletteBox struct {
		members []int
		channel int
		score   float64
	}
	boxes := []paletteBox{{members: members, score: -1}}
	for len(boxes) < 256-first {
		selected, bestScore := -1, 0.0
		for i := range boxes {
			box := &boxes[i]
			if len(box.members) < 2 {
				continue
			}
			if box.score < 0 {
				var mean, variance [4]float64
				weight := 0.0
				for _, member := range box.members {
					weight += weights[member]
					for channel, value := range points[member] {
						mean[channel] += value
					}
				}
				for channel := range mean {
					mean[channel] /= float64(len(box.members))
				}
				for _, member := range box.members {
					for channel, value := range points[member] {
						delta := value - mean[channel]
						variance[channel] += float64(delta * delta)
					}
				}
				maxVariance := 0.0
				for channel, value := range variance {
					value /= float64(len(box.members))
					if value > maxVariance {
						box.channel, maxVariance = channel, value
					}
				}
				// Variance is unweighted; frequency weights only the box score.
				box.score = maxVariance * weight
			}
			if box.score > bestScore {
				selected, bestScore = i, box.score
			}
		}
		if selected < 0 {
			break
		}
		box := boxes[selected]
		// The ordinal preserves stable channel ties without a second comparator.
		order := make([]uint64, len(box.members))
		weight := 0.0
		for i, member := range box.members {
			order[i] = uint64(points[member][box.channel])<<32 | uint64(i)
			weight += weights[member]
		}
		slices.Sort(order)
		ordered := make([]int, len(order))
		cut, cumulative := 0, 0.0
		for i, key := range order {
			ordered[i] = box.members[uint32(key)]
			cumulative += weights[ordered[i]]
			if cut == 0 && cumulative >= weight/2 {
				cut = i + 1
			}
		}
		cut = min(max(cut, 1), len(ordered)-1)
		boxes = append(boxes[:selected], boxes[selected+1:]...)
		boxes = append(boxes, paletteBox{members: ordered[:cut], score: -1}, paletteBox{members: ordered[cut:], score: -1})
	}
	centroids := make([][4]float64, len(boxes))
	for i, box := range boxes {
		weight := 0.0
		for _, member := range box.members {
			weight += weights[member]
			for channel, value := range points[member] {
				centroids[i][channel] += value * weights[member]
			}
		}
		for channel := range centroids[i] {
			centroids[i][channel] /= weight
		}
	}
	assignments := make([]int, len(points))
	for pass := 0; pass <= 8; pass++ {
		// Stream distances; never allocate unique-colors times256 temporary values.
		for i, point := range points {
			best := math.Inf(1)
			for cluster, centroid := range centroids {
				distance := 0.0
				for channel, value := range point {
					delta := value - centroid[channel]
					distance += float64(delta * delta)
				}
				if distance < best {
					best, assignments[i] = distance, cluster
				}
			}
		}
		if pass == 8 {
			break // Final assignment uses the eighth update, before rounding.
		}
		sums := make([][4]float64, len(centroids))
		totals := make([]float64, len(centroids))
		for i, point := range points {
			cluster := assignments[i]
			totals[cluster] += weights[i]
			for channel, value := range point {
				sums[cluster][channel] += value * weights[i]
			}
		}
		for cluster, total := range totals {
			if total > 0 {
				for channel, value := range sums[cluster] {
					centroids[cluster][channel] = value / total
				}
			}
		}
	}
	for i, centroid := range centroids {
		alpha := int(math.RoundToEven(centroid[3]))
		palette[i+first] = color.NRGBA{uint8(math.RoundToEven(centroid[0])), uint8(math.RoundToEven(centroid[1])), uint8(math.RoundToEven(centroid[2])), uint8(min(255, 2*((alpha+1)/2)))}
	}
	for i, value := range colors {
		pixel := color.NRGBA{uint8(value >> 24), uint8(value >> 16), uint8(value >> 8), uint8(value)}
		indices[pixel] = byte(assignments[i] + first)
	}
	return normalized, palette, indices, nil
}
