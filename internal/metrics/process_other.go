//go:build !linux && !android

package metrics

import "errors"

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

func ReadProcess(int) (ProcessSnapshot, error) {
	return ProcessSnapshot{}, errors.New("process metrics are not implemented on this platform")
}

func ProcessDelta(ProcessSnapshot, ProcessSnapshot) (ProcessSnapshot, error) {
	return ProcessSnapshot{}, errors.New("process metrics are not implemented on this platform")
}
