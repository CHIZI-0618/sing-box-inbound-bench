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
