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
	ConntrackCount *uint64                 `json:"conntrack_count,omitempty"`
}

func ReadHost([]string) (HostSnapshot, error) {
	return HostSnapshot{}, errors.New("host metrics are not implemented on this platform")
}
func HostDelta(HostSnapshot, HostSnapshot) (HostSnapshot, error) {
	return HostSnapshot{}, errors.New("host metrics are not implemented on this platform")
}
