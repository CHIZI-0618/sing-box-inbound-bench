package netdev

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Stats struct {
	RXBytes   uint64 `json:"rx_bytes"`
	RXPackets uint64 `json:"rx_packets"`
	RXErrors  uint64 `json:"rx_errors"`
	RXDropped uint64 `json:"rx_dropped"`
	TXBytes   uint64 `json:"tx_bytes"`
	TXPackets uint64 `json:"tx_packets"`
	TXErrors  uint64 `json:"tx_errors"`
	TXDropped uint64 `json:"tx_dropped"`
}

var fields = []struct {
	name string
	set  func(*Stats, uint64)
}{
	{"rx_bytes", func(s *Stats, v uint64) { s.RXBytes = v }},
	{"rx_packets", func(s *Stats, v uint64) { s.RXPackets = v }},
	{"rx_errors", func(s *Stats, v uint64) { s.RXErrors = v }},
	{"rx_dropped", func(s *Stats, v uint64) { s.RXDropped = v }},
	{"tx_bytes", func(s *Stats, v uint64) { s.TXBytes = v }},
	{"tx_packets", func(s *Stats, v uint64) { s.TXPackets = v }},
	{"tx_errors", func(s *Stats, v uint64) { s.TXErrors = v }},
	{"tx_dropped", func(s *Stats, v uint64) { s.TXDropped = v }},
}

func Read(name string) (Stats, error) {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return Stats{}, errors.New("invalid interface name")
	}
	root := filepath.Join("/sys/class/net", name, "statistics")
	var result Stats
	for _, field := range fields {
		content, err := os.ReadFile(filepath.Join(root, field.name))
		if err != nil {
			return Stats{}, fmt.Errorf("read %s: %w", field.name, err)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
		if err != nil {
			return Stats{}, fmt.Errorf("parse %s: %w", field.name, err)
		}
		field.set(&result, value)
	}
	return result, nil
}

func Delta(before, after Stats) (Stats, error) {
	beforeValues := []uint64{before.RXBytes, before.RXPackets, before.RXErrors, before.RXDropped, before.TXBytes, before.TXPackets, before.TXErrors, before.TXDropped}
	afterValues := []uint64{after.RXBytes, after.RXPackets, after.RXErrors, after.RXDropped, after.TXBytes, after.TXPackets, after.TXErrors, after.TXDropped}
	values := make([]uint64, len(beforeValues))
	for index := range beforeValues {
		if afterValues[index] < beforeValues[index] {
			return Stats{}, errors.New("interface counters moved backwards")
		}
		values[index] = afterValues[index] - beforeValues[index]
	}
	return Stats{RXBytes: values[0], RXPackets: values[1], RXErrors: values[2], RXDropped: values[3], TXBytes: values[4], TXPackets: values[5], TXErrors: values[6], TXDropped: values[7]}, nil
}

func Marshal(stats Stats) json.RawMessage {
	data, _ := json.Marshal(stats)
	return data
}
