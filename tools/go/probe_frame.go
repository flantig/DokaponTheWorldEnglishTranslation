package main

import (
	"crypto/sha256"
	"fmt"
	"image"
)

// normalizeProbeFrame consumes an owned decoded raster, discarding alpha while
// preserving hidden RGB, then follows the pinned Pillow RGB640-to64 path.
// PNG mode eligibility and missing-predecessor semantics belong to callers.
func normalizeProbeFrame(raster *image.NRGBA) (*image.NRGBA, []byte, ProbeFrameComparisonResult, error) {
	var facts ProbeFrameComparisonResult
	if raster == nil {
		return nil, nil, facts, fmt.Errorf("frame normalization requires an owned raster")
	}
	for at := 3; at < len(raster.Pix); at += 4 {
		raster.Pix[at] = 255
	}
	current := raster
	var normalized *image.NRGBA
	var hashes [3]string
	var sample []byte
	for stage, size := range []image.Point{raster.Bounds().Size(), {640, 480}, {64, 48}} {
		if stage > 0 {
			resized, err := resizeRaster(current, size.X, size.Y, "bicubic", nil)
			if err != nil {
				return nil, nil, facts, err
			}
			current = resized.(*image.NRGBA)
			if stage == 1 {
				normalized = current
			}
		}
		hasher := sha256.New()
		row := make([]byte, size.X*3)
		if stage == 2 {
			sample = make([]byte, size.X*size.Y*3)
		}
		for y := 0; y < size.Y; y++ {
			for x := 0; x < size.X; x++ {
				copy(row[x*3:x*3+3], current.Pix[y*current.Stride+x*4:y*current.Stride+x*4+3])
			}
			_, _ = hasher.Write(row)
			if stage == 2 {
				copy(sample[y*len(row):(y+1)*len(row)], row)
			}
		}
		hashes[stage] = fmt.Sprintf("%x", hasher.Sum(nil))
	}
	facts.Status = "AVAILABLE"
	facts.SourceRGBSHA256, facts.NormalizedRGBSHA256, facts.ComparisonRGBSHA256 = hashes[0], hashes[1], hashes[2]
	return normalized, sample, facts, nil
}

// compareProbeFrames compares already normalized RGB64 samples. It neither
// selects a retained frame nor invents the caller's explicit first-frame999.
func compareProbeFrames(current, previous []byte) (uint64, float64, error) {
	if len(current) != 64*48*3 || len(previous) != 64*48*3 {
		return 0, 0, fmt.Errorf("frame comparison requires two64x48 RGB samples")
	}
	var sum uint64
	for at, value := range current {
		difference := int(value) - int(previous[at])
		if difference < 0 {
			difference = -difference
		}
		sum += uint64(difference)
	}
	return sum, float64(sum) / float64(64*48*3), nil
}
