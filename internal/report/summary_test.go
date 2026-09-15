package report

import (
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

func TestMedianAndPercentile(t *testing.T) {
	if got := median([]float64{9, 1, 5, 3}); got != 4 {
		t.Fatalf("median=%v", got)
	}
	if got := percentile([]int64{40, 10, 30, 20}, .99); got != 40 {
		t.Fatalf("p99=%v", got)
	}
}

func TestDeliveredBytes(t *testing.T) {
	repetition := protocol.Repetition{Counters: protocol.Counters{BytesSent: 100, BytesReceived: 80}}
	config := protocol.Config{Workload: protocol.WorkloadConfig{Mode: protocol.ModeEcho}}
	if got := deliveredBytes(repetition, config); got != 80 {
		t.Fatalf("delivered=%d", got)
	}
}

func TestOwnedResultPathRejectsEscape(t *testing.T) {
	if _, err := ownedResultPath(t.TempDir(), "../escape.json"); err == nil {
		t.Fatal("accepted escaping path")
	}
}
