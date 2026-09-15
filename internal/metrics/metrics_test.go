//go:build linux || android

package metrics

import (
	"os"
	"testing"
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
