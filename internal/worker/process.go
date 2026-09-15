package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type ProcessHooks struct {
	BeforeStart   func(Ready) error
	AfterWorkload func() error
}

func RunProcess(ctx context.Context, executable, temporaryRoot string, request Request, hooks ProcessHooks) (Result, error) {
	if executable == "" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return Result{}, err
		}
	}
	if temporaryRoot == "" {
		temporaryRoot = os.TempDir()
	}
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		return Result{}, err
	}
	requestFile, err := os.CreateTemp(temporaryRoot, ".inbound-bench-worker-*.json")
	if err != nil {
		return Result{}, err
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)
	if err = requestFile.Chmod(0o600); err == nil {
		err = json.NewEncoder(requestFile).Encode(request)
	}
	if closeErr := requestFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return Result{}, err
	}
	command := exec.CommandContext(ctx, executable, "worker", "-request", requestPath)
	stdin, err := command.StdinPipe()
	if err != nil {
		return Result{}, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		return Result{}, err
	}
	decoder := json.NewDecoder(stdout)
	var ready Ready
	if err = decoder.Decode(&ready); err != nil {
		_ = stdin.Close()
		waitErr := command.Wait()
		return Result{}, fmt.Errorf("worker readiness: %w: %s", errors.Join(err, waitErr), strings.TrimSpace(stderr.String()))
	}
	if ready.ProtocolVersion != protocol.Version || ready.Type != "ready" || ready.Identity.PID != command.Process.Pid {
		_ = command.Process.Kill()
		_ = command.Wait()
		return Result{}, errors.New("worker returned an invalid readiness message")
	}
	if hooks.BeforeStart != nil {
		if err = hooks.BeforeStart(ready); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return Result{}, err
		}
	}
	if _, err = io.WriteString(stdin, "start\n"); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return Result{}, err
	}
	var finished Finished
	if err = decoder.Decode(&finished); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return Result{}, fmt.Errorf("worker completion: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if finished.ProtocolVersion != protocol.Version || finished.Type != "finished" || finished.PID != ready.Identity.PID {
		_ = command.Process.Kill()
		_ = command.Wait()
		return Result{}, errors.New("worker returned an invalid completion message")
	}
	var afterErr error
	if hooks.AfterWorkload != nil {
		afterErr = hooks.AfterWorkload()
	}
	if _, err = io.WriteString(stdin, "collect\n"); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return Result{}, errors.Join(afterErr, err)
	}
	_ = stdin.Close()
	var result Result
	decodeErr := decoder.Decode(&result)
	waitErr := command.Wait()
	if decodeErr != nil || afterErr != nil || waitErr != nil {
		return result, fmt.Errorf("worker result: %w: %s", errors.Join(decodeErr, afterErr, waitErr), strings.TrimSpace(stderr.String()))
	}
	if result.ProtocolVersion != protocol.Version || result.Type != "result" || result.Identity != ready.Identity {
		return Result{}, errors.New("worker returned an invalid result message")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

func TemporaryRoot(configured string) string {
	if configured != "" {
		return filepath.Clean(configured)
	}
	return filepath.Join(os.TempDir(), "sing-box-inbound-bench")
}
