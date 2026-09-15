package runner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

type WarmupFunc func(context.Context) (subject.WarmupEvidence, error)
type MeasureFunc func(context.Context, protocol.PathProof) error

type Report struct {
	Trace     protocol.ExecutionTrace
	PathProof protocol.PathProof
	Artifacts []subject.Artifact
}

// Execute runs one subject transaction. Once Snapshot succeeds,
// VerifyRestore is always attempted. Once Setup or Start is attempted, their
// matching cleanup operation is attempted even when that phase returns an
// error, because a failed operation may have changed partial state.
func Execute(ctx context.Context, selected subject.Subject, warmup WarmupFunc, measure MeasureFunc) (report Report, returnErr error) {
	report.Trace.StartedAt = time.Now()
	if err := runPhase(ctx, &report.Trace, "preflight", selected.Preflight); err != nil {
		report.Trace.FinishedAt = time.Now()
		return report, fmt.Errorf("preflight: %w", err)
	}
	if err := runPhase(ctx, &report.Trace, "snapshot", selected.Snapshot); err != nil {
		report.Trace.FinishedAt = time.Now()
		return report, fmt.Errorf("snapshot: %w", err)
	}
	setupAttempted := false
	startAttempted := false
	defer func() {
		cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancelCleanup()
		if startAttempted {
			if err := runPhase(cleanupContext, &report.Trace, "stop", selected.Stop); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("stop: %w", err))
			}
		}
		if setupAttempted {
			artifacts, err := collectArtifacts(cleanupContext, &report.Trace, selected)
			report.Artifacts = artifacts
			if err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("collect artifacts: %w", err))
			}
			if err = runPhase(cleanupContext, &report.Trace, "cleanup", selected.Cleanup); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup: %w", err))
			}
		}
		if err := runPhase(cleanupContext, &report.Trace, "verify_restore", selected.VerifyRestore); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("verify restore: %w", err))
		} else {
			report.Trace.RestoreVerified = true
		}
		report.Trace.FinishedAt = time.Now()
	}()
	setupAttempted = true
	if err := runPhase(ctx, &report.Trace, "setup", selected.Setup); err != nil {
		return report, fmt.Errorf("setup: %w", err)
	}
	startAttempted = true
	if err := runPhase(ctx, &report.Trace, "start", selected.Start); err != nil {
		return report, fmt.Errorf("start: %w", err)
	}
	before, err := observePhase(ctx, &report.Trace, "observe_path_before", selected)
	if err != nil {
		return report, fmt.Errorf("observe path before warmup: %w", err)
	}
	var warmupEvidence subject.WarmupEvidence
	err = runPhase(ctx, &report.Trace, "warmup", func(ctx context.Context) error {
		var warmupErr error
		warmupEvidence, warmupErr = warmup(ctx)
		return warmupErr
	})
	if err != nil {
		return report, fmt.Errorf("warmup: %w", err)
	}
	after, err := observePhase(ctx, &report.Trace, "observe_path_after", selected)
	if err != nil {
		return report, fmt.Errorf("observe path after warmup: %w", err)
	}
	var proof protocol.PathProof
	err = runPhase(ctx, &report.Trace, "prove_path", func(ctx context.Context) error {
		var proofErr error
		proof, proofErr = selected.ProvePath(ctx, before, after, warmupEvidence)
		return proofErr
	})
	report.PathProof = proof
	if err != nil {
		return report, fmt.Errorf("prove path: %w", err)
	}
	if !proof.Valid {
		return report, errors.New("prove path: subject did not provide valid interception evidence")
	}
	if err = runPhase(ctx, &report.Trace, "measure", func(ctx context.Context) error { return measure(ctx, proof) }); err != nil {
		return report, fmt.Errorf("measure: %w", err)
	}
	return report, nil
}

func runPhase(ctx context.Context, trace *protocol.ExecutionTrace, name string, function func(context.Context) error) error {
	phase := protocol.PhaseResult{Name: name, StartedAt: time.Now()}
	err := function(ctx)
	phase.FinishedAt = time.Now()
	phase.Success = err == nil
	if err != nil {
		phase.Error = err.Error()
	}
	trace.Phases = append(trace.Phases, phase)
	return err
}

func observePhase(ctx context.Context, trace *protocol.ExecutionTrace, name string, selected subject.Subject) (subject.Observation, error) {
	var observation subject.Observation
	err := runPhase(ctx, trace, name, func(ctx context.Context) error {
		var observeErr error
		observation, observeErr = selected.ObservePath(ctx)
		return observeErr
	})
	return observation, err
}

func collectArtifacts(ctx context.Context, trace *protocol.ExecutionTrace, selected subject.Subject) ([]subject.Artifact, error) {
	var artifacts []subject.Artifact
	err := runPhase(ctx, trace, "collect_artifacts", func(ctx context.Context) error {
		var collectErr error
		artifacts, collectErr = selected.Artifacts(ctx)
		return collectErr
	})
	return artifacts, err
}
