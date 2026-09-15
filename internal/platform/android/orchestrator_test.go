package android

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type orchestrationExecutor struct {
	calls   [][]string
	running bool
}

func (e *orchestrationExecutor) Run(_ context.Context, arguments ...string) ([]byte, error) {
	e.calls = append(e.calls, slices.Clone(arguments))
	joined := strings.Join(arguments, " ")
	switch {
	case joined == "shell id -u":
		return []byte("0\n"), nil
	case joined == "shell /manager status":
		if e.running {
			return []byte("running\n"), nil
		}
		return []byte("stopped\n"), nil
	case joined == "shell /manager stop":
		e.running = false
		return nil, nil
	case joined == "shell /manager start":
		e.running = true
		return nil, nil
	case strings.Contains(joined, "/inbound-bench matrix -config"):
		return []byte("matrix failed"), errors.New("exit 1")
	default:
		return []byte("stable"), nil
	}
}

func TestRunDeviceRestoresProductionServiceAfterMatrixFailure(t *testing.T) {
	root := t.TempDir()
	bench := filepath.Join(root, "inbound-bench")
	singBox := filepath.Join(root, "sing-box")
	if err := os.WriteFile(bench, []byte("bench"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(singBox, []byte("sing-box"), 0o700); err != nil {
		t.Fatal(err)
	}
	matrixPath := filepath.Join(root, "matrix.json")
	matrix := protocol.MatrixConfig{
		ProtocolVersion: protocol.Version, MatrixID: "android-test", Seed: 1, OutputDirectory: "ignored",
		Cases: []protocol.Config{{
			ProtocolVersion: protocol.Version, RunID: "raw", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw},
			Workload:  protocol.WorkloadConfig{Protocol: protocol.ProtocolTCP, Mode: protocol.ModeEcho, Target: "192.0.2.1:9000", PayloadBytes: 64, Requests: 1, Connections: 1, Flows: 1, TimeoutMS: 1000},
			Execution: protocol.ExecutionConfig{Repetitions: 1, OutputDirectory: "ignored"},
		}},
	}
	if err := protocol.WriteJSON(matrixPath, matrix); err != nil {
		t.Fatal(err)
	}
	executor := &orchestrationExecutor{running: true}
	_, err := RunDevice(context.Background(), DeviceConfig{
		ProtocolVersion: protocol.Version, RemoteRoot: "/data/local/tmp/sing-box", BenchmarkBinary: bench,
		SingBoxBinary: singBox, MatrixConfig: matrixPath, LocalOutputDirectory: filepath.Join(root, "results"),
		Service: &ServiceConfig{Status: []string{"/manager", "status"}, RunningContains: "running", Stop: []string{"/manager", "stop"}, Start: []string{"/manager", "start"}},
	}, executor)
	if err == nil || !strings.Contains(err.Error(), "remote matrix") {
		t.Fatalf("error=%v", err)
	}
	if !executor.running {
		t.Fatal("production service was not restored")
	}
	if !containsCall(executor.calls, "shell /manager stop") || !containsCall(executor.calls, "shell /manager start") {
		t.Fatalf("calls=%v", executor.calls)
	}
}

func TestRewriteMatrixForDeviceUsesOwnedPaths(t *testing.T) {
	uid := uint32(2000)
	matrix := protocol.MatrixConfig{Cases: []protocol.Config{{
		RunID: "ebpf", Subject: protocol.SubjectConfig{Kind: protocol.SubjectEBPFCgroup, SingBoxBinary: "/host/sing-box"},
		Execution: protocol.ExecutionConfig{WorkerUID: &uid},
	}}}
	rewriteMatrixForDevice(&matrix, "/data/local/tmp/sing-box/inbound-bench-test", "/remote/sing-box")
	config := matrix.Cases[0]
	if config.Subject.SingBoxBinary != "/remote/sing-box" || !strings.HasPrefix(config.Subject.CgroupPath, "/sys/fs/cgroup/sbi-") || !strings.HasPrefix(config.Execution.TemporaryDirectory, "/data/local/tmp/sing-box/inbound-bench-test/") {
		t.Fatalf("config=%+v", config)
	}
}

func TestVerifySnapshotReportsOwnedStateLeak(t *testing.T) {
	before := DeviceSnapshot{Commands: map[string]CommandResult{"ip4-rule": {Output: "one"}}}
	after := DeviceSnapshot{Commands: map[string]CommandResult{"ip4-rule": {Output: "two"}}}
	if err := VerifySnapshot(before, after); err == nil {
		t.Fatal("accepted changed state")
	}
}

func containsCall(calls [][]string, want string) bool {
	return slices.ContainsFunc(calls, func(call []string) bool { return strings.Join(call, " ") == want })
}
