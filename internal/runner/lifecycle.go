package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

type WarmupFunc func(context.Context) (subject.WarmupEvidence, error)
type MeasureFunc func(context.Context, protocol.PathProof) error

// Execute runs one subject transaction. Once Snapshot succeeds,
// VerifyRestore is always attempted. Once Setup or Start is attempted, their
// matching cleanup operation is attempted even when that phase returns an
// error, because a failed operation may have changed partial state.
func Execute(ctx context.Context, selected subject.Subject, warmup WarmupFunc, measure MeasureFunc) (returnErr error) {
	if err := selected.Preflight(ctx); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	if err := selected.Snapshot(ctx); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	setupAttempted := false
	startAttempted := false
	defer func() {
		cleanupContext := context.WithoutCancel(ctx)
		if startAttempted {
			if err := selected.Stop(cleanupContext); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("stop: %w", err))
			}
		}
		if setupAttempted {
			if err := selected.Cleanup(cleanupContext); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup: %w", err))
			}
		}
		if err := selected.VerifyRestore(cleanupContext); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("verify restore: %w", err))
		}
	}()
	setupAttempted = true
	if err := selected.Setup(ctx); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	startAttempted = true
	if err := selected.Start(ctx); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	before, err := selected.ObservePath(ctx)
	if err != nil {
		return fmt.Errorf("observe path before warmup: %w", err)
	}
	warmupEvidence, err := warmup(ctx)
	if err != nil {
		return fmt.Errorf("warmup: %w", err)
	}
	after, err := selected.ObservePath(ctx)
	if err != nil {
		return fmt.Errorf("observe path after warmup: %w", err)
	}
	proof, err := selected.ProvePath(ctx, before, after, warmupEvidence)
	if err != nil {
		return fmt.Errorf("prove path: %w", err)
	}
	if !proof.Valid {
		return errors.New("prove path: subject did not provide valid interception evidence")
	}
	if err = measure(ctx, proof); err != nil {
		return fmt.Errorf("measure: %w", err)
	}
	return nil
}
