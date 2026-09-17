package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/runner"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

func TestFailedRepetitionPreservesExecutionFailureShape(t *testing.T) {
	started := time.Now().Add(-time.Second)
	finished := time.Now()
	repetition := failedRepetition(protocol.Config{RunID: "run-1", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}}, 2, false, runner.Report{
		Trace: protocol.ExecutionTrace{StartedAt: started, FinishedAt: finished},
	})
	if repetition.Validity.Valid || repetition.PathProof.Valid || repetition.PathProof.Method == "" || repetition.DurationNS <= 0 {
		t.Fatalf("repetition=%+v", repetition)
	}
}

func TestWriteArtifactsRecordsContentHash(t *testing.T) {
	root := t.TempDir()
	records, err := writeArtifacts(root, protocol.SubjectDirect, "rep-000", []subject.Artifact{{Name: "stderr.log", Content: []byte("failure\n"), Truncated: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(records[0].SHA256) != 64 || !records[0].Truncated {
		t.Fatalf("records=%+v", records)
	}
	content, err := os.ReadFile(filepath.Join(root, "direct", filepath.FromSlash(records[0].Name)))
	if err != nil || string(content) != "failure\n" {
		t.Fatalf("content=%q err=%v", content, err)
	}
}

func TestWriteArtifactsRejectsTraversal(t *testing.T) {
	_, err := writeArtifacts(t.TempDir(), protocol.SubjectRaw, "rep-000", []subject.Artifact{{Name: "../outside", Content: []byte("x")}})
	if err == nil || !strings.Contains(err.Error(), "invalid artifact") {
		t.Fatalf("error=%v", err)
	}
}

func TestBuildMatrixStateRandomizesByBlockAndWrapsRawControls(t *testing.T) {
	matrix := protocol.MatrixConfig{
		ProtocolVersion: protocol.Version, MatrixID: "matrix", Seed: 42,
		RawControl: &protocol.Config{RunID: "raw-control", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}},
		Cases: []protocol.Config{
			{RunID: "a", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}, Execution: protocol.ExecutionConfig{WarmupRepetitions: 1, Repetitions: 2}},
			{RunID: "b", Subject: protocol.SubjectConfig{Kind: protocol.SubjectDirect}, Execution: protocol.ExecutionConfig{WarmupRepetitions: 1, Repetitions: 2}},
			{RunID: "c", Subject: protocol.SubjectConfig{Kind: protocol.SubjectTun}, Execution: protocol.ExecutionConfig{WarmupRepetitions: 1, Repetitions: 2}},
		},
	}
	first := buildMatrixState(t.TempDir(), matrix)
	second := buildMatrixState(t.TempDir(), matrix)
	if len(first.Jobs) != 15 || len(second.Jobs) != len(first.Jobs) {
		t.Fatalf("jobs=%d", len(first.Jobs))
	}
	for index := range first.Jobs {
		if first.Jobs[index].ID != second.Jobs[index].ID {
			t.Fatal("same seed produced a different order")
		}
	}
	for block := 0; block < 3; block++ {
		offset := block * 5
		if first.Jobs[offset].Control != "before" || first.Jobs[offset+4].Control != "after" {
			t.Fatalf("block %d is not wrapped by controls", block)
		}
	}
}

func TestMatrixRecoveryRequestUsesRawPhysicalTarget(t *testing.T) {
	uid := uint32(2000)
	request := matrixRecoveryRequest(protocol.Config{
		Workload:  protocol.WorkloadConfig{Target: "192.0.2.2:19090"},
		Execution: protocol.ExecutionConfig{WorkerUID: &uid},
	})
	if request.RunID != "matrix-recovery" || request.Workload.Protocol != protocol.ProtocolUDP || request.Workload.Mode != protocol.ModeEcho {
		t.Fatalf("request=%+v", request)
	}
	if request.Workload.Target != "192.0.2.2:19090" || request.Workload.Requests != 8 || request.Workload.TimeoutMS != 500 {
		t.Fatalf("workload=%+v", request.Workload)
	}
	if request.WorkerUID == nil || *request.WorkerUID != uid || request.CollectProof {
		t.Fatalf("request=%+v", request)
	}
}
