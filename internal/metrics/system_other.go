//go:build !linux && !android

package metrics

import "errors"

type SystemSnapshot struct {
	CPUTicks        []uint64          `json:"cpu_ticks"`
	SoftIRQs        map[string]uint64 `json:"softirqs"`
	ContextSwitches uint64            `json:"context_switches"`
	Processes       uint64            `json:"processes"`
}

func ReadSystem() (SystemSnapshot, error) {
	return SystemSnapshot{}, errors.New("system metrics are not implemented on this platform")
}

func SystemDelta(SystemSnapshot, SystemSnapshot) (SystemSnapshot, error) {
	return SystemSnapshot{}, errors.New("system metrics are not implemented on this platform")
}
