package report

import (
	"path/filepath"
	"strings"
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

func TestPPSRatesExcludeDrainTime(t *testing.T) {
	repetition := protocol.Repetition{
		DurationNS: int64(12 * time.Second), Counters: protocol.Counters{Operations: 1900, BytesSent: 1900, BytesReceived: 1900},
		WorkloadTiming: &protocol.WorkloadTiming{ActiveDurationNS: int64(10 * time.Second), DrainDurationNS: int64(2 * time.Second)},
	}
	config := protocol.Config{Workload: protocol.WorkloadConfig{Mode: protocol.ModePPS}}
	value := &caseValues{}
	appendRepetition(value, repetition, config)
	if len(value.ops) != 1 || value.ops[0] != 190 || deliveredBitsPerSecond(repetition, config) != 1520 {
		t.Fatalf("ops=%v bits=%v", value.ops, deliveredBitsPerSecond(repetition, config))
	}
}

func TestSummaryReportsShortConnectionSuccessRate(t *testing.T) {
	value := &caseValues{}
	repetition := protocol.Repetition{
		DurationNS: int64(time.Second), Counters: protocol.Counters{Operations: 63, Failed: 1},
		Validity: protocol.Validity{Valid: true},
	}
	appendRepetition(value, repetition, protocol.Config{})
	summary := summarizeCase(protocol.Config{RunID: "short", Subject: protocol.SubjectConfig{Kind: protocol.SubjectTProxy}}, value)
	if summary.SuccessPercent != 98.4375 || summary.Statistics["success_percent"].Median != 98.4375 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestSummaryReportsShortConnectionPhases(t *testing.T) {
	value := &caseValues{}
	repetition := protocol.Repetition{
		DurationNS: int64(time.Second), Counters: protocol.Counters{Operations: 2},
		LatencyNS: []int64{100, 200}, ConnectLatencyNS: []int64{20, 40}, ApplicationLatencyNS: []int64{70, 150},
		Validity: protocol.Validity{Valid: true},
	}
	appendRepetition(value, repetition, protocol.Config{})
	summary := summarizeCase(protocol.Config{RunID: "short", Subject: protocol.SubjectConfig{Kind: protocol.SubjectTProxy}}, value)
	if summary.ConnectLatencyP50NS != 20 || summary.ConnectLatencyP95NS != 40 || summary.ApplicationLatencyP50NS != 70 || summary.ApplicationLatencyP95NS != 150 {
		t.Fatalf("summary=%+v", summary)
	}
	markdown := string(Markdown(Summary{MatrixID: "test", Cases: []CaseSummary{summary}}))
	if !strings.Contains(markdown, "## TCP short phases") || !strings.Contains(markdown, "| short |") {
		t.Fatalf("markdown=%s", markdown)
	}
}

func TestSummaryReportsHostTCPDiagnostics(t *testing.T) {
	value := &caseValues{}
	repetition := protocol.Repetition{
		DurationNS: int64(time.Second), Counters: protocol.Counters{Operations: 32},
		Resources: protocol.ResourceDelta{SystemTCP: map[string]uint64{
			"Tcp.RetransSegs": 32, "TcpExt.TCPSynRetrans": 32,
			"TcpExt.ListenOverflows": 1, "TcpExt.ListenDrops": 2,
		}},
		Validity: protocol.Validity{Valid: true},
	}
	appendRepetition(value, repetition, protocol.Config{})
	summary := summarizeCase(protocol.Config{RunID: "short", Subject: protocol.SubjectConfig{Kind: protocol.SubjectEBPFCgroup}}, value)
	if summary.TCPRetransSegments != 32 || summary.TCPSynRetransmissions != 32 || summary.TCPListenOverflows != 1 || summary.TCPListenDrops != 2 {
		t.Fatalf("summary=%+v", summary)
	}
	markdown := string(Markdown(Summary{MatrixID: "test", Cases: []CaseSummary{summary}}))
	if !strings.Contains(markdown, "## Host TCP diagnostics") || !strings.Contains(markdown, "| short | 32.0 | 32.0 | 1.0 | 2.0 |") {
		t.Fatalf("markdown=%s", markdown)
	}
}

func TestSummaryIncludesUDPLossInSuccessRate(t *testing.T) {
	value := &caseValues{}
	repetition := protocol.Repetition{
		DurationNS: int64(time.Second), Counters: protocol.Counters{Operations: 90, Lost: 10},
		Validity: protocol.Validity{Valid: true},
	}
	appendRepetition(value, repetition, protocol.Config{})
	summary := summarizeCase(protocol.Config{RunID: "udp", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}}, value)
	if summary.SuccessPercent != 90 || summary.Statistics["success_percent"].Median != 90 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestOptionalIdleMetricsAreNotReportedAsObservedZero(t *testing.T) {
	value := &caseValues{}
	repetition := protocol.Repetition{DurationNS: int64(time.Second), Validity: protocol.Validity{Valid: true}}
	appendRepetition(value, repetition, protocol.Config{})
	summary := summarizeCase(protocol.Config{RunID: "standby", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}}, value)
	if _, exists := summary.Statistics["cpu_idle_transitions_per_second"]; exists {
		t.Fatal("reported unavailable CPU idle counters as zero")
	}
	if _, exists := summary.Statistics["wakeup_count_per_second"]; exists {
		t.Fatal("reported unavailable wakeup counters as zero")
	}
	repetition.Resources.CPUIdleUsage = map[string]uint64{"cpu0/state0": 7}
	repetition.Resources.WakeupSources = map[string]protocol.WakeupSourceCounters{"timer": {EventCount: 5, WakeupCount: 3}}
	value = &caseValues{}
	appendRepetition(value, repetition, protocol.Config{})
	summary = summarizeCase(protocol.Config{RunID: "standby", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}}, value)
	if summary.Statistics["cpu_idle_transitions_per_second"].Samples != 1 || summary.CPUIdleTransitions != 7 {
		t.Fatalf("idle summary=%+v", summary)
	}
	if summary.Statistics["wakeup_count_per_second"].Samples != 1 || summary.WakeupCount != 3 {
		t.Fatalf("wakeup summary=%+v", summary)
	}
}

func TestOwnedResultPathRejectsEscape(t *testing.T) {
	if _, err := ownedResultPath(t.TempDir(), "../escape.json"); err == nil {
		t.Fatal("accepted escaping path")
	}
}
