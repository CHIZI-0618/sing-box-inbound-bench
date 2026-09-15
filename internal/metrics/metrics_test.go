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
