package report

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

func TestMedianAndPercentile(t *testing.T) {
	if got := median([]float64{9, 1, 5, 3}); got != 4 {
		t.Fatalf("median=%v", got)
	}
	if got := percentile([]int64{40, 10, 30, 20}, .99); got != 40 {
		t.Fatalf("p99=%v", got)
	}
	stats := distribution([]float64{1, 2, 3, 4, 100})
	if stats.Samples != 5 || stats.Median != 3 || stats.Q1 != 2 || stats.Q3 != 4 || stats.MAD != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestBuildExcludesCasesFromDriftingRawControlBlock(t *testing.T) {
	root := t.TempDir()
	workload := protocol.WorkloadConfig{Protocol: protocol.ProtocolTCP, Mode: protocol.ModeBulkUpload, PayloadBytes: 100, DurationMS: 1000, Connections: 1, Flows: 1}
	raw := protocol.Config{RunID: "control", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}, Workload: workload}
	config := protocol.Config{RunID: "case", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}, Workload: workload, Execution: protocol.ExecutionConfig{Repetitions: 1}}
	matrix := protocol.MatrixConfig{MatrixID: "test", RawControl: &raw, Cases: []protocol.Config{config}}
	jobs := []protocol.MatrixJob{
		{ID: "before", Control: "before", Block: 0, Result: "before.json", Complete: true},
		{ID: "case", CaseID: "case", Block: 0, Result: "case.json", Complete: true},
		{ID: "after", Control: "after", Block: 0, Result: "after.json", Complete: true},
	}
	write := func(name string, bytes uint64) {
		t.Helper()
		repetition := protocol.Repetition{
			ProtocolVersion: protocol.Version, DurationNS: int64(time.Second), Counters: protocol.Counters{BytesSent: bytes},
			Validity: protocol.Validity{Valid: true},
		}
		if err := protocol.WriteJSON(filepath.Join(root, name), repetition); err != nil {
			t.Fatal(err)
		}
	}
	write("before.json", 100)
	write("case.json", 100)
	write("after.json", 200)
	summary, err := Build(root, matrix, protocol.MatrixState{Jobs: jobs})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Cases) != 1 || summary.Cases[0].ValidRepetitions != 0 || summary.Cases[0].InvalidRepetitions != 1 || len(summary.Warnings) == 0 {
		t.Fatalf("summary=%+v", summary)
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
