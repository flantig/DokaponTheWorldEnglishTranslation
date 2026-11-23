package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ProbeNativeSettings is a serialized, exact-path Flatpak writer handoff, never
// profile configuration. Prepared remains the exclusive writer's original proof.
// The destination and one concurrent save temporary each reserve one MiB; past
// observed temporaries retain their measured exposure for the whole bounded run.
type ProbeNativeSettings struct {
	Prepared ProbeArtifactClaim
	Parent   os.FileInfo
	Values   map[string]string
	Backend  string
	Armed    bool
}

// parseProbeSettings shares the existing literal grammar and refusal precedence.
// Backend-only folded duplicate checks stay distinct from exact duplicate keys;
// the first canonical UI header supplies the lossless version insertion point.
func parseProbeSettings(settings []byte, padBackend string, flatpak bool) (values map[string]string, uiInsertAt int, uiLineEnding string, err error) {
	values, uiInsertAt, uiLineEnding = map[string]string{}, -1, "\n"
	nativeKeys := map[string]bool{}
	section, offset := "", 0
	for _, rawLine := range strings.SplitAfter(string(settings), "\n") {
		offset += len(rawLine)
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if flatpak && strings.EqualFold(section, "UI") {
				if section != "UI" {
					return nil, -1, "", fmt.Errorf("private settings UI section is ambiguous")
				}
				if uiInsertAt < 0 && strings.HasSuffix(rawLine, "\n") {
					uiInsertAt = offset
					if strings.HasSuffix(rawLine, "\r\n") {
						uiLineEnding = "\r\n"
					}
				}
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		name := section + "." + strings.TrimSpace(key)
		_, duplicate := values[name]
		folded := strings.ToLower(name)
		if flatpak && folded == "ui.settingsversion" && (name != "UI.SettingsVersion" || nativeKeys[folded]) {
			return nil, -1, "", fmt.Errorf("private settings version is ambiguous")
		}
		if !found || duplicate || (padBackend == "uinput" || padBackend == "private-x11") && nativeKeys[folded] {
			return nil, -1, "", fmt.Errorf("settings template is not normalized")
		}
		nativeKeys[folded] = true
		values[name] = strings.TrimSpace(value)
	}
	return values, uiInsertAt, uiLineEnding, nil
}

// validateProbeNativeSettings checks the prepared handoff or a normalized native
// replacement through a pinned parent. It publishes no accounting or new pins.
// Inode identity is a read-stability guard, not attribution to an application.
func validateProbeNativeSettings(settings *ProbeNativeSettings, expected os.FileInfo) (os.FileInfo, error) {
	if settings == nil || settings.Prepared.Path == "" || settings.Prepared.ExpectedInfo == nil || settings.Parent == nil || len(settings.Values) == 0 {
		return nil, fmt.Errorf("native settings lack their prepared writer proof")
	}
	path := settings.Prepared.Path
	parent := filepath.Dir(path)
	resolved, resolveErr := filepath.EvalSymlinks(parent)
	info, statErr := os.Lstat(parent)
	if resolveErr != nil || statErr != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || resolved != parent || !info.IsDir() || info.Mode().Perm() != 0700 || !os.SameFile(settings.Parent, info) {
		return nil, fmt.Errorf("native settings parent authority differs")
	}
	directory, err := os.OpenFile(parent, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	openedParent, parentErr := directory.Stat()
	if parentErr != nil || !os.SameFile(info, openedParent) {
		directory.Close()
		return nil, fmt.Errorf("native settings opened parent differs")
	}
	fd, openErr := syscall.Openat(int(directory.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if openErr != nil {
		directory.Close()
		return nil, openErr
	}
	file := os.NewFile(uintptr(fd), path)
	before, beforeErr := file.Stat()
	if beforeErr != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 0 || before.Size() > 1<<20 || expected == nil || !os.SameFile(expected, before) {
		file.Close()
		directory.Close()
		return nil, fmt.Errorf("native settings are not their bounded exclusive file")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		file.Close()
		directory.Close()
		return nil, fmt.Errorf("native settings file ownership differs")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	after, afterErr := file.Stat()
	closeErr := file.Close()
	pathAfter, pathErr := os.Lstat(path)
	parentAfter, parentAfterErr := os.Lstat(parent)
	parentCloseErr := directory.Close()
	if readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || parentAfterErr != nil || parentCloseErr != nil || !os.SameFile(before, after) || !os.SameFile(before, pathAfter) || before.Size() != int64(len(data)) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() || after.Size() != pathAfter.Size() || after.ModTime() != pathAfter.ModTime() || after.Mode() != pathAfter.Mode() || !os.SameFile(settings.Parent, parentAfter) || parentAfter.Mode() != openedParent.Mode() {
		return nil, fmt.Errorf("native settings stable readback differs")
	}
	statAfter, ok := pathAfter.Sys().(*syscall.Stat_t)
	parentStat, parentOK := parentAfter.Sys().(*syscall.Stat_t)
	if !ok || statAfter.Uid != uint32(os.Getuid()) || statAfter.Nlink != 1 || !parentOK || parentStat.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("native settings final ownership differs")
	}
	if !settings.Armed && (!os.SameFile(settings.Prepared.ExpectedInfo, before) || settings.Prepared.ExpectedSHA256 != fmt.Sprintf("%x", sha256.Sum256(data))) {
		return nil, fmt.Errorf("native settings changed before writer handoff")
	}
	values, _, _, err := parseProbeSettings(data, settings.Backend, true)
	if err != nil {
		return nil, err
	}
	for key, value := range settings.Values {
		actual, present := values[key]
		if !present || actual != value {
			return nil, fmt.Errorf("native settings contract differs: %s", key)
		}
	}
	for key := range values {
		if _, original := settings.Values[key]; original {
			continue
		}
		switch key {
		case "UI.MainWindowGeometry", "UI.MainWindowState", "GameListTableView.HeaderState":
		default:
			return nil, fmt.Errorf("native settings have an unadmitted key: %s", key)
		}
	}
	return before, nil
}
