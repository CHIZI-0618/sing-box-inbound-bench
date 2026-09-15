package runner

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

type fakeSubject struct {
	steps  []string
	failAt string
}

func (f *fakeSubject) step(name string) error {
	f.steps = append(f.steps, name)
	if f.failAt == name {
		return errors.New("injected")
	}
	return nil
}
func (*fakeSubject) Kind() protocol.SubjectKind        { return protocol.SubjectRaw }
func (f *fakeSubject) Preflight(context.Context) error { return f.step("preflight") }
func (f *fakeSubject) Snapshot(context.Context) error  { return f.step("snapshot") }
func (f *fakeSubject) Setup(context.Context) error     { return f.step("setup") }
func (f *fakeSubject) Start(context.Context) error     { return f.step("start") }
func (f *fakeSubject) ObservePath(context.Context) (subject.Observation, error) {
	return subject.Observation{CapturedAt: time.Now(), Data: json.RawMessage(`{}`)}, f.step("observe")
}
func (f *fakeSubject) ProvePath(context.Context, subject.Observation, subject.Observation, subject.WarmupEvidence) (protocol.PathProof, error) {
	return protocol.PathProof{Valid: true, ObservedAt: time.Now()}, f.step("prove")
}
func (f *fakeSubject) Stop(context.Context) error { return f.step("stop") }
func (f *fakeSubject) Artifacts(context.Context) ([]subject.Artifact, error) {
	return nil, f.step("collect")
}
func (f *fakeSubject) Cleanup(context.Context) error       { return f.step("cleanup") }
func (f *fakeSubject) VerifyRestore(context.Context) error { return f.step("verify") }

func TestExecuteRollsBackPartialStart(t *testing.T) {
	fake := &fakeSubject{failAt: "start"}
	_, err := Execute(context.Background(), fake, func(context.Context) (subject.WarmupEvidence, error) { return subject.WarmupEvidence{Valid: true}, nil }, func(context.Context, protocol.PathProof) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
	want := []string{"preflight", "snapshot", "setup", "start", "stop", "collect", "cleanup", "verify"}
	if !reflect.DeepEqual(fake.steps, want) {
		t.Fatalf("steps=%v want=%v", fake.steps, want)
	}
}

func TestExecuteRollsBackPartialSetup(t *testing.T) {
	fake := &fakeSubject{failAt: "setup"}
	_, _ = Execute(context.Background(), fake, nil, nil)
	want := []string{"preflight", "snapshot", "setup", "collect", "cleanup", "verify"}
	if !reflect.DeepEqual(fake.steps, want) {
		t.Fatalf("steps=%v want=%v", fake.steps, want)
	}
}

func TestExecuteHappyPath(t *testing.T) {
	fake := &fakeSubject{}
	report, err := Execute(context.Background(), fake, func(context.Context) (subject.WarmupEvidence, error) {
		fake.steps = append(fake.steps, "warmup")
		return subject.WarmupEvidence{Valid: true}, nil
	}, func(context.Context, protocol.PathProof) error {
		fake.steps = append(fake.steps, "measure")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"preflight", "snapshot", "setup", "start", "observe", "warmup", "observe", "prove", "measure", "stop", "collect", "cleanup", "verify"}
	if !reflect.DeepEqual(fake.steps, want) {
		t.Fatalf("steps=%v want=%v", fake.steps, want)
	}
	if !report.Trace.RestoreVerified || len(report.Trace.Phases) != len(want) {
		t.Fatalf("trace=%+v", report.Trace)
	}
}

func TestCleanupFailureIsReportedAndRestoreStillRuns(t *testing.T) {
	fake := &fakeSubject{failAt: "cleanup"}
	report, err := Execute(context.Background(), fake, func(context.Context) (subject.WarmupEvidence, error) {
		return subject.WarmupEvidence{Valid: true}, nil
	}, func(context.Context, protocol.PathProof) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("error=%v", err)
	}
	if !report.Trace.RestoreVerified || fake.steps[len(fake.steps)-1] != "verify" {
		t.Fatalf("trace=%+v steps=%v", report.Trace, fake.steps)
	}
}
