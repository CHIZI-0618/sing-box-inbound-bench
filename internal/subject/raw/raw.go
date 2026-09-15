package raw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

type Subject struct {
	ProcessNames []string
	WorkerUID    *uint32
	found        []string
}

func New(workerUID *uint32) *Subject {
	return &Subject{ProcessNames: []string{"sing-box"}, WorkerUID: workerUID}
}

func (*Subject) Kind() protocol.SubjectKind { return protocol.SubjectRaw }
func (s *Subject) Preflight(context.Context) error {
	var err error
	s.found, err = subject.FindProcesses(s.ProcessNames)
	if err != nil {
		return err
	}
	if len(s.found) > 0 {
		return fmt.Errorf("raw baseline requires sing-box to be stopped; found %s", strings.Join(s.found, ", "))
	}
	return nil
}
func (*Subject) Snapshot(context.Context) error                        { return nil }
func (*Subject) Setup(context.Context) error                           { return nil }
func (*Subject) Start(context.Context) error                           { return nil }
func (*Subject) Stop(context.Context) error                            { return nil }
func (*Subject) Artifacts(context.Context) ([]subject.Artifact, error) { return nil, nil }
func (*Subject) Cleanup(context.Context) error                         { return nil }
func (s *Subject) VerifyRestore(context.Context) error {
	found, err := subject.FindProcesses(s.ProcessNames)
	if err != nil {
		return err
	}
	if len(found) > 0 {
		return fmt.Errorf("sing-box appeared during raw baseline: %s", strings.Join(found, ", "))
	}
	return nil
}
func (s *Subject) ObservePath(context.Context) (subject.Observation, error) {
	found, err := subject.FindProcesses(s.ProcessNames)
	if err != nil {
		return subject.Observation{}, err
	}
	if len(found) > 0 {
		return subject.Observation{}, fmt.Errorf("sing-box appeared during raw path proof: %s", strings.Join(found, ", "))
	}
	data, _ := json.Marshal(map[string]any{"managed_process": false, "rejected_process_names": s.ProcessNames, "matching_processes": found})
	return subject.Observation{CapturedAt: time.Now(), Data: data}, nil
}
func (s *Subject) ProvePath(_ context.Context, before, after subject.Observation, warmup subject.WarmupEvidence) (protocol.PathProof, error) {
	proofError := subject.ValidateSocketPathEvidence(warmup.Details, false, s.WorkerUID, "")
	return protocol.PathProof{
		Valid: warmup.Valid && proofError == nil, Method: "server-confirmed raw socket tuple with no sing-box process found during preflight", ObservedAt: time.Now(),
		Before: before.Data, After: after.Data, Evidence: warmup.Details, Error: errorString(proofError),
	}, nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
