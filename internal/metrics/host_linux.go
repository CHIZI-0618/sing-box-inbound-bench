//go:build linux || android

package metrics

import (
	"bufio"
	"errors"
	"fmt"
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
	CPUIdleTime    map[string]uint64       `json:"cpu_idle_time_microseconds,omitempty"`
	CPUIdleUsage   map[string]uint64       `json:"cpu_idle_usage,omitempty"`
	WakeupSources  map[string]WakeupSource `json:"wakeup_sources,omitempty"`
	ConntrackCount *uint64                 `json:"conntrack_count,omitempty"`
}

type WakeupSource struct {
	EventCount         uint64 `json:"event_count"`
	WakeupCount        uint64 `json:"wakeup_count"`
	TotalTime          uint64 `json:"total_time"`
	PreventSuspendTime uint64 `json:"prevent_suspend_time"`
}

func ReadHost(interfaceNames []string) (HostSnapshot, error) {
	system, err := ReadSystem()
	if err != nil {
		return HostSnapshot{}, err
	}
	result := HostSnapshot{
		System: system, Interfaces: make(map[string]netdev.Stats),
		Thermal:       readGlobValues("/sys/class/thermal/thermal_zone*/temp"),
		CPUFrequency:  readGlobValues("/sys/devices/system/cpu/cpufreq/policy*/scaling_cur_freq"),
		CPUIdleTime:   readRelativeGlobUint64("/sys/devices/system/cpu/cpu*/cpuidle/state*/time", "/sys/devices/system/cpu"),
		CPUIdleUsage:  readRelativeGlobUint64("/sys/devices/system/cpu/cpu*/cpuidle/state*/usage", "/sys/devices/system/cpu"),
		WakeupSources: readWakeupSources("/sys/kernel/debug/wakeup_sources"),
	}
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
	idleTime, idleTimeErr := subtractUint64Maps(before.CPUIdleTime, after.CPUIdleTime)
	idleUsage, idleUsageErr := subtractUint64Maps(before.CPUIdleUsage, after.CPUIdleUsage)
	wakeupSources, wakeupErr := subtractWakeupSources(before.WakeupSources, after.WakeupSources)
	if idleTimeErr != nil || idleUsageErr != nil || wakeupErr != nil {
		return HostSnapshot{}, errors.Join(idleTimeErr, idleUsageErr, wakeupErr)
	}
	result := HostSnapshot{
		System: system, Interfaces: make(map[string]netdev.Stats), Thermal: after.Thermal, CPUFrequency: after.CPUFrequency,
		CPUIdleTime: idleTime, CPUIdleUsage: idleUsage, WakeupSources: wakeupSources, ConntrackCount: after.ConntrackCount,
	}
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

func readRelativeGlobUint64(pattern, root string) map[string]uint64 {
	paths, _ := filepath.Glob(pattern)
	result := make(map[string]uint64)
	for _, itemPath := range paths {
		content, err := os.ReadFile(itemPath)
		if err != nil {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(root, filepath.Dir(itemPath))
		if err == nil {
			result[filepath.ToSlash(relative)] = value
		}
	}
	return result
}

func readWakeupSources(sourcePath string) map[string]WakeupSource {
	file, err := os.Open(sourcePath)
	if err != nil {
		return nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil
	}
	header := strings.Fields(scanner.Text())
	indices := make(map[string]int, len(header))
	for index, name := range header {
		indices[name] = index
	}
	result := make(map[string]WakeupSource)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		read := func(name string) uint64 {
			index, exists := indices[name]
			if !exists || index >= len(fields) {
				return 0
			}
			value, _ := strconv.ParseUint(fields[index], 10, 64)
			return value
		}
		result[fields[0]] = WakeupSource{
			EventCount: read("event_count"), WakeupCount: read("wakeup_count"),
			TotalTime: read("total_time"), PreventSuspendTime: read("prevent_suspend_time"),
		}
	}
	return result
}

func subtractUint64Maps(before, after map[string]uint64) (map[string]uint64, error) {
	result := make(map[string]uint64)
	for name, beforeValue := range before {
		afterValue, exists := after[name]
		if !exists {
			continue
		}
		if afterValue < beforeValue {
			return nil, fmt.Errorf("counter %s moved backwards", name)
		}
		result[name] = afterValue - beforeValue
	}
	return result, nil
}

func subtractWakeupSources(before, after map[string]WakeupSource) (map[string]WakeupSource, error) {
	result := make(map[string]WakeupSource)
	for name, beforeValue := range before {
		afterValue, exists := after[name]
		if !exists {
			continue
		}
		if afterValue.EventCount < beforeValue.EventCount || afterValue.WakeupCount < beforeValue.WakeupCount || afterValue.TotalTime < beforeValue.TotalTime || afterValue.PreventSuspendTime < beforeValue.PreventSuspendTime {
			return nil, fmt.Errorf("wakeup source %s moved backwards", name)
		}
		result[name] = WakeupSource{
			EventCount:         afterValue.EventCount - beforeValue.EventCount,
			WakeupCount:        afterValue.WakeupCount - beforeValue.WakeupCount,
			TotalTime:          afterValue.TotalTime - beforeValue.TotalTime,
			PreventSuspendTime: afterValue.PreventSuspendTime - beforeValue.PreventSuspendTime,
		}
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
