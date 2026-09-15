//go:build !linux && !android

package metrics

import "errors"

type ProcessSnapshot struct {
	UserTicks      uint64 `json:"user_ticks"`
	SystemTicks    uint64 `json:"system_ticks"`
	RunNanoseconds uint64 `json:"run_nanoseconds"`
	ReadBytes      uint64 `json:"read_bytes"`
	WriteBytes     uint64 `json:"write_bytes"`
	RSSBytes       uint64 `json:"rss_bytes"`
}

func ReadProcess(int) (ProcessSnapshot, error) {
	return ProcessSnapshot{}, errors.New("process metrics are not implemented on this platform")
}

func ProcessDelta(ProcessSnapshot, ProcessSnapshot) (ProcessSnapshot, error) {
	return ProcessSnapshot{}, errors.New("process metrics are not implemented on this platform")
}
