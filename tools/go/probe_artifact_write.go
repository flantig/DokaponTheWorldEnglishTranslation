package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// writeProbeArtifact applies lifecycle accounting to the shared exclusive writer.
// Its parent descriptor pins actual creation/readback/cleanup; commit follows
// writer close and parent durability, using the writer's verified inode facts.
// A failed write/Sync/commit retains its reservation, including uncertain cleanup.
// Nil budget preserves the historical writer behavior for unsampled callers.
func writeProbeArtifact(budget *ProbeArtifactBudget, class ProbeArtifactClass, path string, data io.Reader, size int64, digest string, mode os.FileMode) error {
	if budget == nil {
		_, err := writeNewFile(path, nil, data, size, digest, mode)
		return err
	}
	if size < 0 || size == 1<<63-1 {
		return fmt.Errorf("owned artifact requires a bounded nonnegative size")
	}
	if class == probeArtifactFinalizer && uint64(size) > probeFinalizerArtifactBytes {
		return fmt.Errorf("finalizer artifact exceeds its admitted per-output reservation")
	}
	claim := ProbeArtifactClaim{ID: "artifact:" + path, Path: path, MaxFinalBytes: uint64(size), Class: class}
	if err := accountProbeArtifacts(budget, probeArtifactReserve, []ProbeArtifactClaim{claim}); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	resolved, resolveErr := filepath.EvalSymlinks(parent)
	if err != nil || resolveErr != nil || resolved != parent || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("owned artifact parent is not a canonical private0700 directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("owned artifact parent is not owned by this user")
	}
	if pin := budget.Roots[parent]; pin != nil && !os.SameFile(pin, info) {
		return fmt.Errorf("owned artifact parent pin differs")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	opened, statErr := directory.Stat()
	if statErr != nil || !os.SameFile(info, opened) || info.Mode() != opened.Mode() {
		directory.Close()
		return fmt.Errorf("owned artifact opened parent differs")
	}
	budget.Roots[parent] = opened
	verified, writeErr := writeNewFile(path, directory, data, size, digest, mode)
	if writeErr != nil {
		directory.Close()
		return writeErr
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("owned artifact parent durability unknown")
	}
	claim.ExpectedInfo, claim.ExpectedSHA256 = verified, digest
	return accountProbeArtifacts(budget, probeArtifactCommit, []ProbeArtifactClaim{claim})
}
