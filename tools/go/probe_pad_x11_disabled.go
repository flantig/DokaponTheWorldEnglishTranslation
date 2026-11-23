//go:build !linux || !cgo || !nativex11

package main

import (
	"context"
	"fmt"
)

const probeX11Available = false

func emitProbeX11(context.Context, ProbeX11Spec, *ProbeProcessRecord, string, []string, bool) (ProbeX11Effect, error) {
	return ProbeX11Effect{}, fmt.Errorf("private X11 input requires Linux and -tags nativex11 with the XCB SDK")
}
