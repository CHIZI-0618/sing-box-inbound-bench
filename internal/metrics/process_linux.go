//go:build linux || android

package metrics

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ProcessSnapshot struct {
	UserTicks      uint64 `json:"user_ticks"`
	SystemTicks    uint64 `json:"system_ticks"`
	RunNanoseconds uint64 `json:"run_nanoseconds"`
	ReadBytes      uint64 `json:"read_bytes"`
	WriteBytes     uint64 `json:"write_bytes"`
	RSSBytes       uint64 `json:"rss_bytes"`
}

func ReadProcess(pid int) (ProcessSnapshot, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ProcessSnapshot{}, err
	}
	closing := strings.LastIndexByte(string(stat), ')')
	if closing < 0 {
		return ProcessSnapshot{}, errors.New("malformed /proc stat")
	}
	fields := strings.Fields(string(stat[closing+1:]))
	// fields starts at field 3 (state), so utime=14 and stime=15 map to 11 and 12.
	if len(fields) < 13 {
		return ProcessSnapshot{}, errors.New("short /proc stat")
	}
	userTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	systemTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	result := ProcessSnapshot{UserTicks: userTicks, SystemTicks: systemTicks}
	if schedstat, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/schedstat", pid)); readErr == nil {
		parts := strings.Fields(string(schedstat))
		if len(parts) > 0 {
			result.RunNanoseconds, _ = strconv.ParseUint(parts[0], 10, 64)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) && !errors.Is(readErr, os.ErrPermission) {
		return ProcessSnapshot{}, readErr
	}
	if err = readKeyValues(fmt.Sprintf("/proc/%d/io", pid), func(key, value string) {
		switch key {
		case "read_bytes":
			result.ReadBytes, _ = strconv.ParseUint(value, 10, 64)
		case "write_bytes":
			result.WriteBytes, _ = strconv.ParseUint(value, 10, 64)
		}
	}); err != nil && !errors.Is(err, os.ErrPermission) {
		return ProcessSnapshot{}, err
	}
	if err = readKeyValues(fmt.Sprintf("/proc/%d/status", pid), func(key, value string) {
		if key == "VmRSS" {
			parts := strings.Fields(value)
			if len(parts) > 0 {
				kilobytes, parseErr := strconv.ParseUint(parts[0], 10, 64)
				if parseErr == nil {
					result.RSSBytes = kilobytes * 1024
				}
			}
		}
	}); err != nil {
		return ProcessSnapshot{}, err
	}
	return result, nil
}

func ProcessDelta(before, after ProcessSnapshot) (ProcessSnapshot, error) {
	if after.UserTicks < before.UserTicks || after.SystemTicks < before.SystemTicks || after.RunNanoseconds < before.RunNanoseconds || after.ReadBytes < before.ReadBytes || after.WriteBytes < before.WriteBytes {
		return ProcessSnapshot{}, errors.New("process counters moved backwards")
	}
	return ProcessSnapshot{
		UserTicks: after.UserTicks - before.UserTicks, SystemTicks: after.SystemTicks - before.SystemTicks, RunNanoseconds: after.RunNanoseconds - before.RunNanoseconds,
		ReadBytes: after.ReadBytes - before.ReadBytes, WriteBytes: after.WriteBytes - before.WriteBytes, RSSBytes: after.RSSBytes,
	}, nil
}

func readKeyValues(path string, consume func(string, string)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if found {
			consume(key, strings.TrimSpace(value))
		}
	}
	return scanner.Err()
}
