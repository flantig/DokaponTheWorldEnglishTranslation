//go:build !nativefonts || !cgo || !linux

package main

import "fmt"

// textMasks retains the font boundary in builds without native font support.
func textMasks(font []byte, size int, layout string, requests []TextRequest) ([]TextMask, error) {
	return nil, fmt.Errorf("TrueType previews require a Linux CGO build with -tags nativefonts, FreeType headers and libraqm.so.0")
}
