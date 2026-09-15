//go:build linux || android

package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func Join(path string, pid int) error {
	if err := validatePath(path); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return fmt.Errorf("join cgroup: %w", err)
	}
	inside, err := ContainsPID(path, pid)
	if err != nil {
		return err
	}
	if !inside {
		return errors.New("cgroup membership was not observable after join")
	}
	return nil
}

func ContainsPID(path string, pid int) (bool, error) {
	if err := validatePath(path); err != nil {
		return false, err
	}
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, err
	}
	defer file.Close()
	want := strconv.Itoa(pid)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == want {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func validatePath(path string) error {
	root := filepath.Clean("/sys/fs/cgroup")
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("cgroup path must name a dedicated child below /sys/fs/cgroup")
	}
	return nil
}
