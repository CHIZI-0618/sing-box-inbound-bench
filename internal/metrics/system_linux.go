//go:build linux || android

package metrics

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
)

type SystemSnapshot struct {
	CPUTicks        []uint64          `json:"cpu_ticks"`
	SoftIRQs        map[string]uint64 `json:"softirqs"`
	ContextSwitches uint64            `json:"context_switches"`
	Processes       uint64            `json:"processes"`
}

func ReadSystem() (SystemSnapshot, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return SystemSnapshot{}, err
	}
	defer file.Close()
	result := SystemSnapshot{}
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
		}
	}
	if err = scanner.Err(); err != nil {
		return SystemSnapshot{}, err
	}
	result.SoftIRQs, err = readSoftIRQs()
	return result, err
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
	result := SystemSnapshot{CPUTicks: make([]uint64, len(before.CPUTicks)), SoftIRQs: make(map[string]uint64)}
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
	for key, beforeValue := range before.SoftIRQs {
		afterValue := after.SoftIRQs[key]
		if afterValue < beforeValue {
			return SystemSnapshot{}, errors.New("softirq counters moved backwards")
		}
		result.SoftIRQs[key] = afterValue - beforeValue
	}
	return result, nil
}
