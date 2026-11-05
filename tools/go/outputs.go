package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// writeNewFile streams a size/digest-bound artifact into an exclusive new file.
// It verifies the copy and readback; failure removes only its own inode.
// Image patch transactions retain their source replanning in patchCopy.
func writeNewFile(path string, data io.Reader, size int64, digest string, mode os.FileMode) (err error) {
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != sha256.Size || size < 0 || size == 1<<63-1 || data == nil {
		return fmt.Errorf("standalone output requires a reader, size and full SHA256")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	owned, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if current, statErr := os.Lstat(path); err != nil && statErr == nil && os.SameFile(owned, current) {
			_ = os.Remove(path)
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(data, size+1))
	if err != nil {
		return err
	}
	if n != size || !bytes.Equal(hash.Sum(nil), expected) {
		return fmt.Errorf("standalone input size or digest mismatch")
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash.Reset()
	n, err = io.Copy(hash, io.LimitReader(file, size+1))
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(owned, current) || n != size || !bytes.Equal(hash.Sum(nil), expected) {
		return fmt.Errorf("standalone output readback or identity mismatch")
	}
	return nil
}
