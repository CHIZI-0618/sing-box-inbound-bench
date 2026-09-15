package subject

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FindProcesses returns exact /proc comm matches. A disappearing or
// unreadable process is skipped because process exit races are expected.
func FindProcesses(names []string) ([]string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	var found []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid == os.Getpid() {
			continue
		}
		content, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, os.ErrPermission) {
				continue
			}
			return nil, readErr
		}
		name := strings.TrimSpace(string(content))
		if _, matches := wanted[name]; matches {
			found = append(found, fmt.Sprintf("%s(pid=%d)", name, pid))
		}
	}
	return found, nil
}
