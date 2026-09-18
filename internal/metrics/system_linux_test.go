//go:build linux || android

package metrics

import (
	"strings"
	"testing"
)

func TestReadProtocolCountersSelectsTCPDiagnostics(t *testing.T) {
	input := strings.NewReader(
		"Tcp: ActiveOpens PassiveOpens RetransSegs InErrs OutRsts\n" +
			"Tcp: 10 20 30 40 50\n" +
			"TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPSynRetrans TCPTimeouts\n" +
			"TcpExt: 1 2 3 4 5\n",
	)
	counters, err := readProtocolCounters(input, selectedTCPStats)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{
		"Tcp.ActiveOpens": 10, "Tcp.PassiveOpens": 20, "Tcp.RetransSegs": 30,
		"Tcp.InErrs": 40, "Tcp.OutRsts": 50, "TcpExt.SyncookiesSent": 1,
		"TcpExt.ListenOverflows": 2, "TcpExt.ListenDrops": 3,
		"TcpExt.TCPSynRetrans": 4, "TcpExt.TCPTimeouts": 5,
	}
	if len(counters) != len(want) {
		t.Fatalf("counters=%v", counters)
	}
	for name, value := range want {
		if counters[name] != value {
			t.Fatalf("%s=%d, want %d", name, counters[name], value)
		}
	}
}

func TestReadProtocolCountersRejectsMismatchedRows(t *testing.T) {
	_, err := readProtocolCounters(strings.NewReader("Tcp: A B\nTcp: 1\n"), map[string]bool{"Tcp.A": true})
	if err == nil {
		t.Fatal("accepted mismatched protocol counter rows")
	}
}

func TestSystemDeltaIncludesTCPDiagnostics(t *testing.T) {
	before := SystemSnapshot{
		CPUTicks: []uint64{1}, CPUByCore: map[string][]uint64{"cpu0": {1}}, SoftIRQs: map[string]uint64{"NET_RX": 1},
		TCP: map[string]uint64{"Tcp.RetransSegs": 10, "TcpExt.TCPSynRetrans": 5},
	}
	after := SystemSnapshot{
		CPUTicks: []uint64{2}, CPUByCore: map[string][]uint64{"cpu0": {2}}, SoftIRQs: map[string]uint64{"NET_RX": 2},
		TCP: map[string]uint64{"Tcp.RetransSegs": 13, "TcpExt.TCPSynRetrans": 7},
	}
	delta, err := SystemDelta(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if delta.TCP["Tcp.RetransSegs"] != 3 || delta.TCP["TcpExt.TCPSynRetrans"] != 2 {
		t.Fatalf("TCP delta=%v", delta.TCP)
	}
}
