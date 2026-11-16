package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const probeFlatpakAppID = "net.pcsx2.PCSX2"
const probePINEDefaultSlot = "28011"

// ProbeLifecycleProcesses keeps launcher disposal separate from emulator exit.
// Only Native/Candidates have passed the exact runtime identity contract.
type ProbeLifecycleProcesses struct {
	Command          *exec.Cmd
	Launcher         *ProbeProcessRecord
	Native           *ProbeProcessRecord
	Candidates       []ProbeProcessRecord
	Unqualified      []ProbeProcessRecord
	NativeExited     bool
	LauncherReaped   bool
	Launched         bool
	Epoch            int
	CleanupAttempts  int
	Startup          *RegistryInput
	BootstrapPending bool
}

// observeProbeProcess is the shared kernel-observation contract. A nil expected
// identity permits only an explicitly launched child to be observed for adoption;
// callers still bind its argv. For a prior identity, os.ErrProcessDone denotes only
// absent stat or matching terminal state. Other errors never establish exit.
func observeProbeProcess(runtime ProbeMemoryRuntime, pid int, expected *ProbeProcessRecord, build string) (ProbeProcessRecord, error) {
	var observed ProbeProcessRecord
	procRoot := "/proc"
	if runtime.Provenance == "synthetic_peer" || runtime.Provenance == "synthetic_flatpak" {
		procRoot = filepath.Join(runtime.Root, "proc")
	}
	processRoot := filepath.Join(procRoot, strconv.Itoa(pid))
	hasExpectedIdentity := expected != nil && pid > 0 && expected.PID == pid && expected.Starttime > 0
	if runtime.Provenance == "synthetic_peer" || runtime.Provenance == "synthetic_flatpak" {
		paths := []string{procRoot, processRoot, filepath.Join(processRoot, "stat"), filepath.Join(processRoot, "cmdline"), filepath.Join(processRoot, "exe")}
		if runtime.Provenance == "synthetic_flatpak" || expected != nil && expected.PINESocket != "" {
			paths = append(paths, filepath.Join(processRoot, "environ"))
		}
		for _, path := range paths {
			info, err := os.Lstat(path)
			if err != nil && path != procRoot && os.IsNotExist(err) && hasExpectedIdentity {
				continue
			}
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return observed, fmt.Errorf("synthetic probe process paths must not traverse symlinks")
			}
		}
	}
	statFile, statErr := os.Open(filepath.Join(processRoot, "stat"))
	if statErr != nil {
		root, rootErr := os.Lstat(procRoot)
		if os.IsNotExist(statErr) && hasExpectedIdentity && rootErr == nil && root.IsDir() {
			return observed, fmt.Errorf("probe runtime process stat unavailable: %w", os.ErrProcessDone)
		}
		return observed, fmt.Errorf("probe runtime process stat unavailable")
	}
	statBytes, readErr := io.ReadAll(io.LimitReader(statFile, 65537))
	_ = statFile.Close()
	end := bytes.LastIndexByte(statBytes, ')')
	fields := []string{}
	if end >= 0 {
		fields = strings.Fields(string(statBytes[end+1:]))
	}
	if readErr != nil || len(statBytes) > 65536 || len(fields) < 20 {
		return observed, fmt.Errorf("probe runtime process identity is stale")
	}
	starttime, parseErr := strconv.ParseUint(fields[19], 10, 64)
	pidText, _, _ := strings.Cut(string(statBytes), " ")
	actualPID, parsePIDErr := strconv.Atoi(pidText)
	if parseErr != nil || parsePIDErr != nil || actualPID != pid || expected != nil && (expected.PID != pid || expected.Starttime == 0 || starttime != expected.Starttime) {
		return observed, fmt.Errorf("probe runtime process identity is stale")
	}
	if fields[0] == "Z" || fields[0] == "X" {
		if hasExpectedIdentity {
			return observed, fmt.Errorf("probe runtime process identity is stale: %w", os.ErrProcessDone)
		}
		return ProbeProcessRecord{PID: pid, Starttime: starttime, State: fields[0]}, fmt.Errorf("probe runtime process identity is stale")
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
	if exeErr != nil || hashErr != nil || afterErr != nil || !before.Mode().IsRegular() || count < 1 || count > 256<<20 || count != before.Size() || before.Size() != after.Size() || before.ModTime() != after.ModTime() || runtime.Provenance != "owned_launcher" && fmt.Sprintf("%x", hasher.Sum(nil)) != build {
		return observed, fmt.Errorf("probe runtime executable build differs")
	}
	if runtime.Provenance == "owned_flatpak" || runtime.Provenance == "synthetic_flatpak" || expected != nil && expected.PINESocket != "" {
		environment, err := os.Open(filepath.Join(processRoot, "environ"))
		if err != nil {
			return observed, fmt.Errorf("owned emulator environment unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(environment, (1<<20)+1))
		_ = environment.Close()
		if readErr != nil || len(data) > 1<<20 {
			return observed, fmt.Errorf("owned emulator environment exceeds bounded contract")
		}
		runtimeDir, found := "/tmp", false
		for _, entry := range strings.Split(string(data), "\x00") {
			key, value, _ := strings.Cut(entry, "=")
			if key == "XDG_RUNTIME_DIR" {
				if found || !filepath.IsAbs(value) || filepath.Clean(value) != value {
					return observed, fmt.Errorf("owned emulator runtime directory is ambiguous")
				}
				runtimeDir, found = value, true
			}
		}
		observed.PINESocket = filepath.Join(runtimeDir, "pcsx2.sock")
		observed.EnvironmentSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
		if expected != nil && (expected.PINESocket != observed.PINESocket || expected.EnvironmentSHA256 != observed.EnvironmentSHA256) {
			return observed, fmt.Errorf("owned emulator namespace endpoint changed")
		}
	}
	return observed, nil
}

// selectProbeProcesses is the shared source-PCXS2 discovery boundary. A nil PID
// scope scans only the selected proc root; offline callers restrict that scope.
// Unqualified candidates are evidence of uncertainty, never signaling authority.
func selectProbeProcesses(runtime ProbeMemoryRuntime, pids []int, build string, expectedArgs []string, notBefore uint64) (matched []ProbeProcessRecord, unqualified []ProbeProcessRecord, result error) {
	procRoot := "/proc"
	if runtime.Provenance == "synthetic_peer" || runtime.Provenance == "synthetic_flatpak" {
		procRoot = filepath.Join(runtime.Root, "proc")
		runtime.Provenance = "synthetic_flatpak"
	} else {
		runtime.Provenance = "owned_flatpak"
	}
	if pids == nil {
		entries, err := os.ReadDir(procRoot)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err == nil && pid > 0 {
				pids = append(pids, pid)
			}
		}
	}
	for _, pid := range pids {
		if runtime.Provenance == "synthetic_flatpak" {
			for _, path := range []string{procRoot, filepath.Join(procRoot, strconv.Itoa(pid)), filepath.Join(procRoot, strconv.Itoa(pid), "comm")} {
				info, err := os.Lstat(path)
				if err != nil || info.Mode()&os.ModeSymlink != 0 {
					return matched, unqualified, fmt.Errorf("synthetic process selection paths must not traverse symlinks")
				}
			}
		}
		comm, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("process candidate %d name unavailable", pid))
			unqualified = append(unqualified, ProbeProcessRecord{PID: pid})
			continue
		}
		name, readErr := io.ReadAll(io.LimitReader(comm, 257))
		_ = comm.Close()
		if readErr != nil || len(name) > 256 {
			result = errors.Join(result, fmt.Errorf("process candidate %d name malformed", pid))
			unqualified = append(unqualified, ProbeProcessRecord{PID: pid})
			continue
		}
		if !strings.Contains(strings.ToLower(string(name)), "pcsx2") {
			continue
		}
		observed, err := observeProbeProcess(runtime, pid, nil, build)
		if (observed.State == "Z" || observed.State == "X") && observed.Starttime > 0 {
			continue
		}
		if observed.PID == 0 {
			observed.PID = pid
		}
		if err != nil || observed.Starttime < notBefore || expectedArgs != nil && !slices.Equal(observed.Cmdline, expectedArgs) {
			result = errors.Join(result, fmt.Errorf("source emulator candidate %d is unqualified: %v", pid, err))
			unqualified = append(unqualified, observed)
			continue
		}
		matched = append(matched, observed)
	}
	return matched, unqualified, result
}

// terminateProbeProcesses is the sole signal/reap owner for stop and failure
// finalization. Launcher reaping never proves native exit or unlocks card writes.
func terminateProbeProcesses(state *ProbeLifecycleProcesses, runtime ProbeMemoryRuntime, build string, timeout time.Duration) (exitedBeforeStop bool, result error) {
	if !state.Launched || state.NativeExited && state.LauncherReaped && len(state.Unqualified) == 0 {
		return false, nil
	}
	if strings.HasPrefix(runtime.Provenance, "synthetic_") {
		return false, fmt.Errorf("synthetic process facts never authorize signaling")
	}
	if goruntime.GOOS != "linux" || goruntime.GOARCH != "amd64" {
		return false, fmt.Errorf("stable process signaling requires the qualified Linux amd64 ABI")
	}
	state.CleanupAttempts++
	deadline := time.Now().Add(timeout)
	known := append([]ProbeProcessRecord{}, state.Candidates...)
	if state.Native != nil {
		known = append(known, *state.Native)
	}
	seen := map[string]bool{}
	remaining := []ProbeProcessRecord{}
	observationErrors := []string{}
	for _, identity := range known {
		key := fmt.Sprintf("%d:%d", identity.PID, identity.Starttime)
		if seen[key] {
			continue
		}
		seen[key] = true
		// pidfd_open binds before revalidation; never fall back to a numeric PID.
		descriptor, _, openErr := syscall.Syscall(434, uintptr(identity.PID), 0, 0)
		if openErr != 0 {
			if openErr == syscall.ESRCH {
				_, err := observeProbeProcess(runtime, identity.PID, &identity, build)
				if errors.Is(err, os.ErrProcessDone) {
					exitedBeforeStop = true
					continue
				}
			}
			remaining = append(remaining, identity)
			result = errors.Join(result, fmt.Errorf("stable native handle unavailable: %w", openErr))
			continue
		}
		_, err := observeProbeProcess(runtime, identity.PID, &identity, build)
		if errors.Is(err, os.ErrProcessDone) {
			_ = syscall.Close(int(descriptor))
			exitedBeforeStop = true
			continue
		}
		if err != nil {
			_ = syscall.Close(int(descriptor))
			remaining = append(remaining, identity)
			result = errors.Join(result, err)
			continue
		}
		_, _, signalErr := syscall.Syscall6(424, descriptor, uintptr(syscall.SIGTERM), 0, 0, 0, 0)
		_ = syscall.Close(int(descriptor))
		if signalErr != 0 && signalErr != syscall.ESRCH {
			remaining = append(remaining, identity)
			result = errors.Join(result, signalErr)
			continue
		}
		stopped := false
		var lastObservationError error
		for time.Now().Before(deadline) {
			_, err := observeProbeProcess(runtime, identity.PID, &identity, build)
			if errors.Is(err, os.ErrProcessDone) {
				stopped = true
				break
			}
			if err != nil {
				if lastObservationError == nil || err.Error() != lastObservationError.Error() {
					observationErrors = append(observationErrors, fmt.Sprintf("%d: %v", identity.PID, err))
				}
				lastObservationError = err
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !stopped {
			remaining = append(remaining, identity)
			result = errors.Join(result, lastObservationError, fmt.Errorf("owned native exit remains unconfirmed"))
		}
	}
	state.Candidates = remaining
	if len(known) > 0 && len(remaining) == 0 {
		state.Native = nil
		state.NativeExited = len(state.Unqualified) == 0
	}
	if state.Command != nil && !state.LauncherReaped {
		if !state.NativeExited {
			// This handle is our unreaped direct child, including a wrapper that
			// changed executable. It never grants authority over unknown natives.
			_ = state.Command.Process.Signal(syscall.SIGTERM)
		}
		for time.Now().Before(deadline) {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(state.Command.Process.Pid, &status, syscall.WNOHANG, nil)
			if err != nil {
				result = errors.Join(result, fmt.Errorf("owned launcher wait failed: %w", err))
				break
			}
			if pid == state.Command.Process.Pid {
				_ = state.Command.Process.Release()
				state.Command = nil
				state.LauncherReaped = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !state.NativeExited || !state.LauncherReaped || len(state.Unqualified) != 0 {
		result = errors.Join(result, fmt.Errorf("native exit and launcher disposal are not both proven"))
	}
	detail, _ := json.Marshal(map[string]any{"native_exited": state.NativeExited, "launcher_reaped": state.LauncherReaped, "remaining_owned": state.Candidates, "unqualified": state.Unqualified, "post_signal_observation_errors": observationErrors, "error": fmt.Sprint(result)})
	path := filepath.Join(runtime.Root, fmt.Sprintf("cleanup-epoch-%d-%d.json", state.Epoch, state.CleanupAttempts))
	if err := writeNewFile(path, bytes.NewReader(detail), int64(len(detail)), fmt.Sprintf("%x", sha256.Sum256(detail)), 0600); err != nil {
		result = errors.Join(result, err)
	}
	return exitedBeforeStop, result
}
