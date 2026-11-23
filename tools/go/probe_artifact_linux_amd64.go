//go:build linux && amd64

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// renameProbeArtifact moves one basename within an open directory without
// replacing any destination. Identity checks and directory sync belong to its
// caller. Unsupported kernels/filesystems refuse; there is no overwrite fallback.
func renameProbeArtifact(parent *os.File, oldBase, newBase string) error {
	if parent == nil || oldBase == "" || newBase == "" || oldBase == newBase || oldBase == "." || oldBase == ".." || newBase == "." || newBase == ".." || filepath.Base(oldBase) != oldBase || filepath.Base(newBase) != newBase {
		return fmt.Errorf("artifact rename requires distinct basenames and an open parent")
	}
	info, err := parent.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("artifact rename parent is not a directory")
	}
	oldName, err := syscall.BytePtrFromString(oldBase)
	if err != nil {
		return err
	}
	newName, err := syscall.BytePtrFromString(newBase)
	if err != nil {
		return err
	}
	// Linux asm/unistd_64.h and linux/fs.h define this ABI and no-replace flag.
	const renameat2, renameNoReplace = 316, 1
	_, _, errno := syscall.Syscall6(renameat2, parent.Fd(), uintptr(unsafe.Pointer(oldName)), parent.Fd(), uintptr(unsafe.Pointer(newName)), renameNoReplace, 0)
	runtime.KeepAlive(parent)
	if errno != 0 {
		return &os.LinkError{Op: "rename_noreplace", Old: oldBase, New: newBase, Err: errno}
	}
	return nil
}
