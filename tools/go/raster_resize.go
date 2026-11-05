package main

import (
	"fmt"
	"image"
	"math"
	"strings"
)

// resizeRaster matches Pillow 12.3 LANCZOS or NEAREST for Gray and NRGBA.
// It returns a fresh image at origin zero and leaves source pixels/padding intact.
// Q22 rounding, clipped byte intermediates and premultiplied filtering are part
// of the artwork contract; identity preserves hidden RGB before any conversion.
// NEAREST alone accepts a crop relative to the source content origin; outside
// pixels are zero padded before sampling. Its larger output bound is for previews.
// Derived from Pillow's Resample.c/Convert.c/Geometry.c; see licenses/Pillow.txt.
func resizeRaster(source image.Image, width, height int, filter string, crop *image.Rectangle) (image.Image, error) {
	var pixels []byte
	var bounds image.Rectangle
	stride, channels := 0, 0
	switch raster := source.(type) {
	case *image.Gray:
		if raster != nil {
			pixels, bounds, stride, channels = raster.Pix, raster.Rect, raster.Stride, 1
		}
	case *image.NRGBA:
		if raster != nil {
			pixels, bounds, stride, channels = raster.Pix, raster.Rect, raster.Stride, 4
		}
	default:
		return nil, fmt.Errorf("resizing requires Gray or NRGBA")
	}
	w, h := bounds.Dx(), bounds.Dy()
	filter, thumbnail := strings.CutPrefix(filter, "thumbnail-")
	if filter != "lanczos" && filter != "nearest" || crop != nil && (filter != "nearest" || thumbnail) {
		return nil, fmt.Errorf("resize requires lanczos or nearest; crop requires nearest")
	}
	for i, size := range []image.Point{{w, h}, {width, height}} {
		axisLimit, pixelLimit := 4096, 1<<20
		if i == 1 && filter == "nearest" {
			axisLimit, pixelLimit = 16384, 1<<24
		}
		if size.X < 1 || size.Y < 1 || size.X > axisLimit || size.Y > axisLimit || size.X*size.Y > pixelLimit {
			return nil, fmt.Errorf("resize dimensions exceed bounds")
		}
	}
	if thumbnail {
		if width >= w && height >= h {
			width, height = w, h
		} else {
			aspect := float64(w) / float64(h)
			if float64(width)/float64(height) >= aspect {
				exact := float64(height) * aspect
				low, high := int(math.Floor(exact)), int(math.Ceil(exact))
				width = low
				if math.Abs(aspect-float64(high)/float64(height)) < math.Abs(aspect-float64(low)/float64(height)) {
					width = high
				}
				width = max(width, 1)
			} else {
				exact := float64(width) / aspect
				low, high := int(math.Floor(exact)), int(math.Ceil(exact))
				height = low
				lowError := 0.0
				if low != 0 {
					lowError = math.Abs(aspect - float64(width)/float64(low))
				}
				if math.Abs(aspect-float64(width)/float64(high)) < lowError {
					height = high
				}
				height = max(height, 1)
			}
		}
	}
	rowBytes := w * channels
	if channels == 0 || stride < rowBytes || len(pixels) < rowBytes || h > 1 && stride > (len(pixels)-rowBytes)/(h-1) {
		return nil, fmt.Errorf("invalid resize source storage")
	}
	if filter == "nearest" {
		view := image.Rect(0, 0, w, h)
		if crop != nil {
			view = *crop
			if view.Min.X < -1<<30 || view.Min.Y < -1<<30 || view.Max.X > 1<<30 || view.Max.Y > 1<<30 || view.Max.X <= view.Min.X || view.Max.Y <= view.Min.Y || view.Dx() > 4096 || view.Dy() > 4096 || view.Dx()*view.Dy() > 1<<20 {
				return nil, fmt.Errorf("nearest crop exceeds bounds")
			}
		}
		columns := make([]int, width)
		stepX, stepY := float64(view.Dx())/float64(width), float64(view.Dy())/float64(height)
		coordinate := stepX * 0.5
		for x := range columns {
			columns[x] = int(coordinate) + view.Min.X
			// Sequential accumulation is observable: Pillow's 2-to-7 map is 0000111.
			coordinate += stepX
		}
		data := make([]byte, width*height*channels)
		coordinate = stepY * 0.5
		for y := 0; y < height; y++ {
			sy := int(coordinate) + view.Min.Y
			coordinate += stepY
			if sy < 0 || sy >= h {
				continue
			}
			for x, sx := range columns {
				if sx < 0 || sx >= w {
					continue
				}
				from, to := sy*stride+sx*channels, (y*width+x)*channels
				copy(data[to:to+channels], pixels[from:from+channels])
			}
		}
		if channels == 4 {
			return &image.NRGBA{Pix: data, Stride: width * 4, Rect: image.Rect(0, 0, width, height)}, nil
		}
		return &image.Gray{Pix: data, Stride: width, Rect: image.Rect(0, 0, width, height)}, nil
	}
	order := []int{0, 1}
	if h > 100*w && height < h {
		// Pillow reverses these passes to bound work on very tall images.
		order[0], order[1] = 1, 0
	}
	intermediate := width * h
	if order[0] == 1 {
		intermediate = w * height
	}
	if intermediate > 1<<20 {
		return nil, fmt.Errorf("resize intermediate exceeds bounds")
	}
	data := make([]byte, rowBytes*h)
	for y := 0; y < h; y++ {
		copy(data[y*rowBytes:(y+1)*rowBytes], pixels[y*stride:y*stride+rowBytes])
	}
	changed := w != width || h != height
	if channels == 4 && changed {
		for i := 0; i < len(data); i += 4 {
			for c := 0; c < 3; c++ {
				value := int(data[i+c])*int(data[i+3]) + 128
				data[i+c] = byte(((value >> 8) + value) >> 8)
			}
		}
	}
	for _, axis := range order {
		inputSize, outputSize := w, width
		outWidth, outHeight := width, h
		if axis == 1 {
			inputSize, outputSize = h, height
			outWidth, outHeight = w, height
		}
		if inputSize == outputSize {
			continue
		}
		scale := float64(inputSize) / float64(outputSize)
		filterScale := max(scale, 1)
		support, inverseScale := 3*filterScale, 1/filterScale
		starts := make([]int, outputSize)
		coefficients := make([][]int64, outputSize)
		for at := 0; at < outputSize; at++ {
			center := (float64(at) + 0.5) * scale
			start := max(0, int(center-support+0.5))
			end := min(inputSize, int(center+support+0.5))
			weights := make([]float64, end-start)
			total := 0.0
			for i := range weights {
				x := (float64(i+start) - center + 0.5) * inverseScale
				weight := 0.0
				if x >= -3 && x < 3 {
					weight = 1
					if x != 0 {
						angle := x * math.Pi
						other := (x / 3) * math.Pi
						weight = (math.Sin(angle) / angle) * (math.Sin(other) / other)
					}
				}
				weights[i] = weight
				total += weight
			}
			starts[at] = start
			coefficients[at] = make([]int64, len(weights))
			for i, weight := range weights {
				weight /= total
				quantized := weight * (1 << 22)
				if weight < 0 {
					quantized -= 0.5
				} else {
					quantized += 0.5
				}
				coefficients[at][i] = int64(quantized)
			}
		}
		filtered := make([]byte, outWidth*outHeight*channels)
		for y := 0; y < outHeight; y++ {
			for x := 0; x < outWidth; x++ {
				at, offset, step := x, y*w*channels, channels
				if axis == 1 {
					at, offset, step = y, x*channels, w*channels
				}
				offset += starts[at] * step
				for c := 0; c < channels; c++ {
					sum := int64(1 << 21)
					for i, coefficient := range coefficients[at] {
						sum += int64(data[offset+i*step+c]) * coefficient
					}
					filtered[(y*outWidth+x)*channels+c] = byte(max(0, min(255, sum>>22)))
				}
			}
		}
		data, w, h = filtered, outWidth, outHeight
	}
	if channels == 4 {
		if changed {
			for i := 0; i < len(data); i += 4 {
				alpha := int(data[i+3])
				if alpha == 0 || alpha == 255 {
					continue
				}
				for c := 0; c < 3; c++ {
					data[i+c] = byte(min(255, 255*int(data[i+c])/alpha))
				}
			}
		}
		return &image.NRGBA{Pix: data, Stride: width * 4, Rect: image.Rect(0, 0, width, height)}, nil
	}
	return &image.Gray{Pix: data, Stride: width, Rect: image.Rect(0, 0, width, height)}, nil
}
