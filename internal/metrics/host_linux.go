//go:build linux || android

package metrics

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/netdev"
)

type HostSnapshot struct {
	System         SystemSnapshot          `json:"system"`
	Interfaces     map[string]netdev.Stats `json:"interfaces,omitempty"`
	Thermal        map[string]int64        `json:"thermal_millicelsius,omitempty"`
	CPUFrequency   map[string]int64        `json:"cpu_frequency_khz,omitempty"`
	ConntrackCount *uint64                 `json:"conntrack_count,omitempty"`
}

func ReadHost(interfaceNames []string) (HostSnapshot, error) {
	system, err := ReadSystem()
	if err != nil {
		return HostSnapshot{}, err
	}
	result := HostSnapshot{System: system, Interfaces: make(map[string]netdev.Stats), Thermal: readGlobValues("/sys/class/thermal/thermal_zone*/temp"), CPUFrequency: readGlobValues("/sys/devices/system/cpu/cpufreq/policy*/scaling_cur_freq")}
	for _, name := range interfaceNames {
		if name == "" {
			continue
		}
		stats, readErr := netdev.Read(name)
		if readErr != nil {
			return HostSnapshot{}, readErr
		}
		result.Interfaces[name] = stats
	}
	if content, readErr := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); readErr == nil {
		value, parseErr := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
		if parseErr == nil {
			result.ConntrackCount = &value
		}
	}
	return result, nil
}

func HostDelta(before, after HostSnapshot) (HostSnapshot, error) {
	system, err := SystemDelta(before.System, after.System)
	if err != nil {
		return HostSnapshot{}, err
	}
	result := HostSnapshot{System: system, Interfaces: make(map[string]netdev.Stats), Thermal: after.Thermal, CPUFrequency: after.CPUFrequency, ConntrackCount: after.ConntrackCount}
	for name, beforeStats := range before.Interfaces {
		afterStats, exists := after.Interfaces[name]
		if !exists {
			return HostSnapshot{}, errors.New("measured interface disappeared")
		}
		delta, deltaErr := netdev.Delta(beforeStats, afterStats)
		if deltaErr != nil {
			return HostSnapshot{}, deltaErr
		}
		result.Interfaces[name] = delta
	}
	return result, nil
}

func readGlobValues(pattern string) map[string]int64 {
	paths, _ := filepath.Glob(pattern)
	result := make(map[string]int64)
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
		if err == nil {
			result[filepath.Base(filepath.Dir(path))] = value
		}
	}
	return result
}
