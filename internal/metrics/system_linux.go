//go:build linux || android

package metrics

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

type SystemSnapshot struct {
	CPUTicks        []uint64            `json:"cpu_ticks"`
	CPUByCore       map[string][]uint64 `json:"cpu_by_core"`
	SoftIRQs        map[string]uint64   `json:"softirqs"`
	ContextSwitches uint64              `json:"context_switches"`
	Processes       uint64              `json:"processes"`
	PageFaults      uint64              `json:"page_faults"`
	MajorPageFaults uint64              `json:"major_page_faults"`
	Migrations      uint64              `json:"migrations"`
	TCP             map[string]uint64   `json:"tcp,omitempty"`
}

var selectedTCPStats = map[string]bool{
	"Tcp.ActiveOpens":        true,
	"Tcp.PassiveOpens":       true,
	"Tcp.AttemptFails":       true,
	"Tcp.EstabResets":        true,
	"Tcp.RetransSegs":        true,
	"Tcp.InErrs":             true,
	"Tcp.OutRsts":            true,
	"TcpExt.SyncookiesSent":  true,
	"TcpExt.SyncookiesRecv":  true,
	"TcpExt.ListenOverflows": true,
	"TcpExt.ListenDrops":     true,
	"TcpExt.TCPLossProbes":   true,
	"TcpExt.TCPTimeouts":     true,
	"TcpExt.TCPSynRetrans":   true,
	"TcpExt.TCPFastRetrans":  true,
	"TcpExt.TCPSpuriousRTOs": true,
	"TcpExt.TCPBacklogDrop":  true,
}

func ReadSystem() (SystemSnapshot, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return SystemSnapshot{}, err
	}
	defer file.Close()
	result := SystemSnapshot{CPUByCore: make(map[string][]uint64)}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "cpu":
			for _, field := range fields[1:] {
				value, parseErr := strconv.ParseUint(field, 10, 64)
				if parseErr != nil {
					return SystemSnapshot{}, parseErr
				}
				result.CPUTicks = append(result.CPUTicks, value)
			}
		case "ctxt":
			result.ContextSwitches, _ = strconv.ParseUint(fields[1], 10, 64)
		case "processes":
			result.Processes, _ = strconv.ParseUint(fields[1], 10, 64)
		default:
			if strings.HasPrefix(fields[0], "cpu") && len(fields[0]) > 3 {
				for _, field := range fields[1:] {
					value, parseErr := strconv.ParseUint(field, 10, 64)
					if parseErr != nil {
						return SystemSnapshot{}, parseErr
					}
					result.CPUByCore[fields[0]] = append(result.CPUByCore[fields[0]], value)
				}
			}
		}
	}
	if err = scanner.Err(); err != nil {
		return SystemSnapshot{}, err
	}
	result.SoftIRQs, err = readSoftIRQs()
	if err != nil {
		return result, err
	}
	_ = readWhitespaceValues("/proc/vmstat", func(key, value string) {
		switch key {
		case "pgfault":
			result.PageFaults, _ = strconv.ParseUint(value, 10, 64)
		case "pgmajfault":
			result.MajorPageFaults, _ = strconv.ParseUint(value, 10, 64)
		case "pgmigrate_success":
			result.Migrations, _ = strconv.ParseUint(value, 10, 64)
		}
	})
	result.TCP = make(map[string]uint64)
	for _, path := range []string{"/proc/net/snmp", "/proc/net/netstat"} {
		counters, readErr := readProtocolCountersFile(path, selectedTCPStats)
		if readErr != nil {
			continue
		}
		for name, value := range counters {
			result.TCP[name] = value
		}
	}
	if len(result.TCP) == 0 {
		result.TCP = nil
	}
	return result, nil
}

func readProtocolCountersFile(path string, selected map[string]bool) (map[string]uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readProtocolCounters(file, selected)
}

func readProtocolCounters(reader io.Reader, selected map[string]bool) (map[string]uint64, error) {
	result := make(map[string]uint64)
	headers := make(map[string][]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		section := strings.TrimSuffix(fields[0], ":")
		if previous, exists := headers[section]; !exists {
			headers[section] = fields[1:]
		} else {
			values := fields[1:]
			if len(values) != len(previous) {
				return nil, errors.New("protocol counter field count changed")
			}
			for index, name := range previous {
				qualified := section + "." + name
				if !selected[qualified] {
					continue
				}
				value, parseErr := strconv.ParseUint(values[index], 10, 64)
				if parseErr != nil {
					return nil, parseErr
				}
				result[qualified] = value
			}
			delete(headers, section)
		}
	}
	return result, scanner.Err()
}

func readWhitespaceValues(path string, consume func(string, string)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			consume(fields[0], fields[1])
		}
	}
	return scanner.Err()
}

func readSoftIRQs() (map[string]uint64, error) {
	file, err := os.Open("/proc/softirqs")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make(map[string]uint64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		if name != "NET_RX" && name != "NET_TX" {
			continue
		}
		for _, field := range fields[1:] {
			value, parseErr := strconv.ParseUint(field, 10, 64)
			if parseErr != nil {
				return nil, parseErr
			}
			result[name] += value
		}
	}
	return result, scanner.Err()
}

func SystemDelta(before, after SystemSnapshot) (SystemSnapshot, error) {
	if len(before.CPUTicks) != len(after.CPUTicks) {
		return SystemSnapshot{}, errors.New("CPU field count changed")
	}
	result := SystemSnapshot{
		CPUTicks: make([]uint64, len(before.CPUTicks)), CPUByCore: make(map[string][]uint64),
		SoftIRQs: make(map[string]uint64), TCP: make(map[string]uint64),
	}
	for index := range before.CPUTicks {
		if after.CPUTicks[index] < before.CPUTicks[index] {
			return SystemSnapshot{}, errors.New("CPU counters moved backwards")
		}
		result.CPUTicks[index] = after.CPUTicks[index] - before.CPUTicks[index]
	}
	if after.ContextSwitches < before.ContextSwitches || after.Processes < before.Processes {
		return SystemSnapshot{}, errors.New("system counters moved backwards")
	}
	result.ContextSwitches = after.ContextSwitches - before.ContextSwitches
	result.Processes = after.Processes - before.Processes
	if after.PageFaults < before.PageFaults || after.MajorPageFaults < before.MajorPageFaults || after.Migrations < before.Migrations {
		return SystemSnapshot{}, errors.New("VM counters moved backwards")
	}
	result.PageFaults = after.PageFaults - before.PageFaults
	result.MajorPageFaults = after.MajorPageFaults - before.MajorPageFaults
	result.Migrations = after.Migrations - before.Migrations
	for name, beforeTicks := range before.CPUByCore {
		afterTicks, exists := after.CPUByCore[name]
		if !exists || len(beforeTicks) != len(afterTicks) {
			return SystemSnapshot{}, errors.New("per-CPU field count changed")
		}
		delta := make([]uint64, len(beforeTicks))
		for index := range beforeTicks {
			if afterTicks[index] < beforeTicks[index] {
				return SystemSnapshot{}, errors.New("per-CPU counters moved backwards")
			}
			delta[index] = afterTicks[index] - beforeTicks[index]
		}
		result.CPUByCore[name] = delta
	}
	for key, beforeValue := range before.SoftIRQs {
		afterValue := after.SoftIRQs[key]
		if afterValue < beforeValue {
			return SystemSnapshot{}, errors.New("softirq counters moved backwards")
		}
		result.SoftIRQs[key] = afterValue - beforeValue
	}
	for key, beforeValue := range before.TCP {
		afterValue, exists := after.TCP[key]
		if !exists {
			continue
		}
		if afterValue < beforeValue {
			return SystemSnapshot{}, errors.New("TCP counters moved backwards")
		}
		result.TCP[key] = afterValue - beforeValue
	}
	if len(result.TCP) == 0 {
		result.TCP = nil
	}
	return result, nil
}
