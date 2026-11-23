//go:build !linux || !amd64

package main

import (
	"fmt"
	"os"
)

func renameProbeArtifact(*os.File, string, string) error {
	return fmt.Errorf("artifact no-replace rename requires the qualified Linux amd64 ABI")
}
