//go:build !linux && !android

package metrics

import "errors"

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

func ReadSystem() (SystemSnapshot, error) {
	return SystemSnapshot{}, errors.New("system metrics are not implemented on this platform")
}

func SystemDelta(SystemSnapshot, SystemSnapshot) (SystemSnapshot, error) {
	return SystemSnapshot{}, errors.New("system metrics are not implemented on this platform")
}
