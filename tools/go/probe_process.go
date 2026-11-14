package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

// observeProbeProcess is the shared kernel-observation contract. A nil expected
// identity permits only an explicitly launched child to be observed for adoption;
// callers still bind its argv. No saved receipt establishes kernel ownership.
func observeProbeProcess(runtime ProbeMemoryRuntime, pid int, expected *ProbeProcessRecord, build string) (ProbeProcessRecord, error) {
	var observed ProbeProcessRecord
	procRoot := "/proc"
	if runtime.Provenance == "synthetic_peer" {
		procRoot = filepath.Join(runtime.Root, "proc")
	}
	processRoot := filepath.Join(procRoot, strconv.Itoa(pid))
	if runtime.Provenance == "synthetic_peer" {
		for _, path := range []string{procRoot, processRoot, filepath.Join(processRoot, "stat"), filepath.Join(processRoot, "cmdline"), filepath.Join(processRoot, "exe")} {
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return observed, fmt.Errorf("synthetic probe process paths must not traverse symlinks")
			}
		}
	}
	statFile, statErr := os.Open(filepath.Join(processRoot, "stat"))
	if statErr != nil {
		return observed, fmt.Errorf("probe runtime process stat unavailable")
	}
	statBytes, readErr := io.ReadAll(io.LimitReader(statFile, 65537))
	_ = statFile.Close()
	end := bytes.LastIndexByte(statBytes, ')')
	fields := []string{}
	if end >= 0 {
		fields = strings.Fields(string(statBytes[end+1:]))
	}
	if readErr != nil || len(statBytes) > 65536 || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return observed, fmt.Errorf("probe runtime process identity is stale")
	}
	starttime, parseErr := strconv.ParseUint(fields[19], 10, 64)
	pidText, _, _ := strings.Cut(string(statBytes), " ")
	actualPID, parsePIDErr := strconv.Atoi(pidText)
	if parseErr != nil || parsePIDErr != nil || actualPID != pid || expected != nil && starttime != expected.Starttime {
		return observed, fmt.Errorf("probe runtime process identity is stale")
	}
	observed = ProbeProcessRecord{PID: pid, Starttime: starttime, State: fields[0]}
	cmdFile, cmdErr := os.Open(filepath.Join(processRoot, "cmdline"))
	if cmdErr != nil {
		return observed, fmt.Errorf("probe runtime process command unavailable")
	}
	cmdBytes, cmdErr := io.ReadAll(io.LimitReader(cmdFile, 65537))
	_ = cmdFile.Close()
	observed.Cmdline = strings.Split(strings.TrimSuffix(string(cmdBytes), "\x00"), "\x00")
	if cmdErr != nil || len(cmdBytes) > 65536 || expected != nil && !reflect.DeepEqual(observed.Cmdline, expected.Cmdline) {
		return observed, fmt.Errorf("probe runtime process command changed")
	}
	executable, exeErr := os.Open(filepath.Join(processRoot, "exe"))
	if exeErr != nil {
		return observed, fmt.Errorf("probe runtime executable unavailable")
	}
	before, exeErr := executable.Stat()
	hasher := sha256.New()
	count, hashErr := io.Copy(hasher, io.LimitReader(executable, (256<<20)+1))
	after, afterErr := executable.Stat()
	_ = executable.Close()
	if exeErr != nil || hashErr != nil || afterErr != nil || !before.Mode().IsRegular() || count < 1 || count > 256<<20 || count != before.Size() || before.Size() != after.Size() || before.ModTime() != after.ModTime() || fmt.Sprintf("%x", hasher.Sum(nil)) != build {
		return observed, fmt.Errorf("probe runtime executable build differs")
	}
	return observed, nil
}
