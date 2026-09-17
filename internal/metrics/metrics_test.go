//go:build linux || android

package metrics

import (
	"os"
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/netdev"
)

func TestReadSelfAndSystem(t *testing.T) {
	if snapshot, err := ReadProcess(os.Getpid()); err != nil || snapshot.UserTicks+snapshot.SystemTicks == 0 && snapshot.RSSBytes == 0 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if snapshot, err := ReadSystem(); err != nil || len(snapshot.CPUTicks) == 0 || snapshot.SoftIRQs == nil {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
}

func TestProcessDeltaRejectsBackwardsCounters(t *testing.T) {
	if _, err := ProcessDelta(ProcessSnapshot{UserTicks: 2}, ProcessSnapshot{UserTicks: 1}); err == nil {
		t.Fatal("accepted backwards counters")
	}
}

func TestReadBPFMapInfo(t *testing.T) {
	path := t.TempDir() + "/fdinfo"
	content := "map_type:\t1\nkey_size:\t4\nvalue_size:\t16\nmax_entries:\t1024\nmap_flags:\t0x1\nmemlock:\t65536\nmap_id:\t42\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := readBPFMapInfo(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != 42 || info.Type != 1 || info.KeySize != 4 || info.ValueSize != 16 || info.MaxEntries != 1024 || info.Flags != 1 || info.Memlock != 65536 {
		t.Fatalf("info=%+v", info)
	}
}

func TestHostDeltaIncludesIdleAndWakeupCounters(t *testing.T) {
	before := HostSnapshot{
		System:     SystemSnapshot{CPUTicks: []uint64{1}, CPUByCore: map[string][]uint64{}, SoftIRQs: map[string]uint64{}},
		Interfaces: map[string]netdev.Stats{}, CPUIdleTime: map[string]uint64{"cpu0/cpuidle/state0": 10},
		CPUIdleUsage:  map[string]uint64{"cpu0/cpuidle/state0": 2},
		WakeupSources: map[string]WakeupSource{"timer": {EventCount: 5, WakeupCount: 3, TotalTime: 7, PreventSuspendTime: 1}},
	}
	after := before
	after.System.CPUTicks = []uint64{2}
	after.CPUIdleTime = map[string]uint64{"cpu0/cpuidle/state0": 25}
	after.CPUIdleUsage = map[string]uint64{"cpu0/cpuidle/state0": 6}
	after.WakeupSources = map[string]WakeupSource{"timer": {EventCount: 9, WakeupCount: 5, TotalTime: 12, PreventSuspendTime: 3}}
	delta, err := HostDelta(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if delta.CPUIdleTime["cpu0/cpuidle/state0"] != 15 || delta.CPUIdleUsage["cpu0/cpuidle/state0"] != 4 {
		t.Fatalf("idle delta=%+v/%+v", delta.CPUIdleTime, delta.CPUIdleUsage)
	}
	if got := delta.WakeupSources["timer"]; got.EventCount != 4 || got.WakeupCount != 2 || got.TotalTime != 5 || got.PreventSuspendTime != 2 {
		t.Fatalf("wakeup delta=%+v", got)
	}
}
