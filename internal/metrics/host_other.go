//go:build !linux && !android

package metrics

import (
	"errors"

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

func ReadHost([]string) (HostSnapshot, error) {
	return HostSnapshot{}, errors.New("host metrics are not implemented on this platform")
}
func HostDelta(HostSnapshot, HostSnapshot) (HostSnapshot, error) {
	return HostSnapshot{}, errors.New("host metrics are not implemented on this platform")
}
