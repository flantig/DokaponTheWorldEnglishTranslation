package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// observeProbeStorage reads only explicit pinned private directories. It returns
// available bytes, with no resource policy or effects; callers decide whether
// low space blocks work. The serialized lifecycle owns the budget and its pins.
func observeProbeStorage(budget *ProbeArtifactBudget, paths []string) (minimumFree uint64, err error) {
	if budget == nil || len(paths) == 0 {
		return 0, fmt.Errorf("storage observation requires owned directory pins and paths")
	}
	minimumFree = ^uint64(0)
	seen := map[string]bool{}
	for _, path := range paths {
		pin := budget.Roots[path]
		snapshotPin := budget.SnapshotRoots[path]
		if pin != nil && snapshotPin != nil && !os.SameFile(pin, snapshotPin) {
			return 0, fmt.Errorf("storage observation directory pins conflict at %s", path)
		}
		if pin == nil {
			pin = snapshotPin
		}
		if pin == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return 0, fmt.Errorf("storage observation lacks a canonical private pin at %s", path)
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		info, pathErr := os.Lstat(path)
		canonical, canonicalErr := filepath.EvalSymlinks(path)
		if pathErr != nil || canonicalErr != nil || canonical != path || !os.SameFile(pin, info) || !info.IsDir() || info.Mode().Perm() != 0700 {
			return 0, fmt.Errorf("storage observation path authority differs at %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			return 0, fmt.Errorf("storage observation path owner differs at %s", path)
		}
		directory, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		opened, openErr := directory.Stat()
		if openErr != nil || !os.SameFile(pin, opened) || opened.Mode() != info.Mode() {
			directory.Close()
			return 0, fmt.Errorf("storage observation descriptor authority differs at %s", path)
		}
		openedStat, ok := opened.Sys().(*syscall.Stat_t)
		if !ok || openedStat.Uid != uint32(os.Getuid()) {
			directory.Close()
			return 0, fmt.Errorf("storage observation descriptor owner differs at %s", path)
		}
		var disk syscall.Statfs_t
		spaceErr := syscall.Fstatfs(int(directory.Fd()), &disk)
		closeErr := directory.Close()
		if spaceErr != nil || closeErr != nil || disk.Bsize <= 0 || disk.Bavail > ^uint64(0)/uint64(disk.Bsize) {
			return 0, fmt.Errorf("storage observation unavailable at %s", path)
		}
		current, currentErr := os.Lstat(path)
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if currentErr != nil || resolveErr != nil || resolved != path || !os.SameFile(pin, current) || current.Mode() != opened.Mode() {
			return 0, fmt.Errorf("storage observation path changed at %s", path)
		}
		currentStat, ok := current.Sys().(*syscall.Stat_t)
		if !ok || currentStat.Uid != uint32(os.Getuid()) {
			return 0, fmt.Errorf("storage observation owner changed at %s", path)
		}
		minimumFree = min(minimumFree, disk.Bavail*uint64(disk.Bsize))
	}
	return minimumFree, nil
}
