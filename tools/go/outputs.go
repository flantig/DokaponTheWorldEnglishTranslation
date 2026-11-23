package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// writeNewFile streams a size/digest-bound artifact into an exclusive new file.
// A nonnil parent anchors creation, entry readback and owned cleanup to that
// caller-owned directory descriptor; nil preserves the original path behavior.
// verified comes from the writer descriptor after stable readback and is cleared
// on any failure, including deferred Close. Parent durability belongs to callers.
func writeNewFile(path string, parent *os.File, data io.Reader, size int64, digest string, mode os.FileMode) (verified os.FileInfo, err error) {
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != sha256.Size || size < 0 || size == 1<<63-1 || data == nil {
		return nil, fmt.Errorf("standalone output requires a reader, size and full SHA256")
	}
	var file *os.File
	if parent == nil {
		file, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
	} else {
		var fd int
		fd, err = syscall.Openat(int(parent.Fd()), filepath.Base(path), syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, uint32(mode.Perm()))
		if err == nil {
			file = os.NewFile(uintptr(fd), path)
		}
	}
	if err != nil {
		return nil, err
	}
	owned, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			return
		}
		verified = nil
		var current os.FileInfo
		var statErr error
		if parent == nil {
			current, statErr = os.Lstat(path)
		} else {
			fd, openErr := syscall.Openat(int(parent.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			statErr = openErr
			if openErr == nil {
				entry := os.NewFile(uintptr(fd), path)
				current, statErr = entry.Stat()
				_ = entry.Close()
			}
		}
		if statErr == nil && os.SameFile(owned, current) {
			if parent == nil {
				_ = os.Remove(path)
			} else {
				_ = syscall.Unlinkat(int(parent.Fd()), filepath.Base(path))
			}
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(data, size+1))
	if err != nil {
		return nil, err
	}
	if n != size || !bytes.Equal(hash.Sum(nil), expected) {
		return nil, fmt.Errorf("standalone input size or digest mismatch")
	}
	if err = file.Sync(); err != nil {
		return nil, err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	hash.Reset()
	n, err = io.Copy(hash, io.LimitReader(file, size+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	var current os.FileInfo
	if parent == nil {
		current, err = os.Lstat(path)
	} else {
		var fd int
		fd, err = syscall.Openat(int(parent.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err == nil {
			entry := os.NewFile(uintptr(fd), path)
			current, err = entry.Stat()
			closeErr := entry.Close()
			if err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if !os.SameFile(owned, after) || !os.SameFile(owned, current) || after.Size() != size || current.Size() != size || after.ModTime() != current.ModTime() || n != size || !bytes.Equal(hash.Sum(nil), expected) {
		return nil, fmt.Errorf("standalone output readback or identity mismatch")
	}
	return after, nil
}
