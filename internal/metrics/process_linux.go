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
	UserTicks             uint64 `json:"user_ticks"`
	SystemTicks           uint64 `json:"system_ticks"`
	RunNanoseconds        uint64 `json:"run_nanoseconds"`
	ReadBytes             uint64 `json:"read_bytes"`
	WriteBytes            uint64 `json:"write_bytes"`
	RSSBytes              uint64 `json:"rss_bytes"`
	PSSBytes              uint64 `json:"pss_bytes"`
	USSBytes              uint64 `json:"uss_bytes"`
	HighWaterRSSBytes     uint64 `json:"high_water_rss_bytes"`
	SwapBytes             uint64 `json:"swap_bytes"`
	MinorFaults           uint64 `json:"minor_faults"`
	MajorFaults           uint64 `json:"major_faults"`
	VoluntarySwitches     uint64 `json:"voluntary_switches"`
	InvoluntarySwitches   uint64 `json:"involuntary_switches"`
	Threads               uint64 `json:"threads"`
	FileDescriptors       uint64 `json:"file_descriptors"`
	SocketFileDescriptors uint64 `json:"socket_file_descriptors"`
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
	minorFaults, err := strconv.ParseUint(fields[7], 10, 64)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	majorFaults, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	result := ProcessSnapshot{UserTicks: userTicks, SystemTicks: systemTicks, MinorFaults: minorFaults, MajorFaults: majorFaults}
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
		switch key {
		case "VmRSS", "VmHWM", "VmSwap":
			parts := strings.Fields(value)
			if len(parts) > 0 {
				kilobytes, parseErr := strconv.ParseUint(parts[0], 10, 64)
				if parseErr == nil {
					switch key {
					case "VmRSS":
						result.RSSBytes = kilobytes * 1024
					case "VmHWM":
						result.HighWaterRSSBytes = kilobytes * 1024
					case "VmSwap":
						result.SwapBytes = kilobytes * 1024
					}
				}
			}
		case "Threads":
			result.Threads, _ = strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		case "voluntary_ctxt_switches":
			result.VoluntarySwitches, _ = strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		case "nonvoluntary_ctxt_switches":
			result.InvoluntarySwitches, _ = strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		}
	}); err != nil {
		return ProcessSnapshot{}, err
	}
	if err = readKeyValues(fmt.Sprintf("/proc/%d/smaps_rollup", pid), func(key, value string) {
		parts := strings.Fields(value)
		if len(parts) == 0 {
			return
		}
		kilobytes, parseErr := strconv.ParseUint(parts[0], 10, 64)
		if parseErr != nil {
			return
		}
		switch key {
		case "Pss":
			result.PSSBytes = kilobytes * 1024
		case "Private_Clean", "Private_Dirty", "Private_Hugetlb":
			result.USSBytes += kilobytes * 1024
		}
	}); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		return ProcessSnapshot{}, err
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err == nil {
		result.FileDescriptors = uint64(len(entries))
		for _, entry := range entries {
			target, readErr := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
			if readErr == nil && strings.HasPrefix(target, "socket:[") {
				result.SocketFileDescriptors++
			}
		}
	} else if !errors.Is(err, os.ErrPermission) {
		return ProcessSnapshot{}, err
	}
	return result, nil
}

func ProcessDelta(before, after ProcessSnapshot) (ProcessSnapshot, error) {
	if after.UserTicks < before.UserTicks || after.SystemTicks < before.SystemTicks || after.RunNanoseconds < before.RunNanoseconds || after.ReadBytes < before.ReadBytes || after.WriteBytes < before.WriteBytes || after.MinorFaults < before.MinorFaults || after.MajorFaults < before.MajorFaults || after.VoluntarySwitches < before.VoluntarySwitches || after.InvoluntarySwitches < before.InvoluntarySwitches {
		return ProcessSnapshot{}, errors.New("process counters moved backwards")
	}
	return ProcessSnapshot{
		UserTicks: after.UserTicks - before.UserTicks, SystemTicks: after.SystemTicks - before.SystemTicks, RunNanoseconds: after.RunNanoseconds - before.RunNanoseconds,
		ReadBytes: after.ReadBytes - before.ReadBytes, WriteBytes: after.WriteBytes - before.WriteBytes,
		MinorFaults: after.MinorFaults - before.MinorFaults, MajorFaults: after.MajorFaults - before.MajorFaults,
		VoluntarySwitches: after.VoluntarySwitches - before.VoluntarySwitches, InvoluntarySwitches: after.InvoluntarySwitches - before.InvoluntarySwitches,
		RSSBytes: after.RSSBytes, PSSBytes: after.PSSBytes, USSBytes: after.USSBytes, HighWaterRSSBytes: after.HighWaterRSSBytes,
		SwapBytes: after.SwapBytes, Threads: after.Threads, FileDescriptors: after.FileDescriptors, SocketFileDescriptors: after.SocketFileDescriptors,
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
