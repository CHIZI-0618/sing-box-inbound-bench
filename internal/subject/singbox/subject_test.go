package singbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/runner"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

func TestOwnedRunDirectory(t *testing.T) {
	root := t.TempDir()
	if _, err := ownedRunDirectory(root, "../escape"); err == nil {
		t.Fatal("accepted escaping run ID")
	}
	path, err := ownedRunDirectory(root, "run-1")
	if err != nil || path == root {
		t.Fatalf("path=%q err=%v", path, err)
	}
}

func TestValidateEBPFDiagnostics(t *testing.T) {
	data := []byte(`{"ebpf":[{"tag":"benchmark-ebpf-in","state":"normal","local_enabled":true,"local_data_plane":"cgroup","attachments":[{"interface_name":"/sys/fs/cgroup/bench","role":"local","mechanism":"cgroup"}]}]}`)
	valid, message, err := validateEBPFDiagnostics(data, protocol.SubjectConfig{Kind: protocol.SubjectEBPFCgroup, CgroupPath: "/sys/fs/cgroup/bench"})
	if err != nil || !valid || message != "" {
		t.Fatalf("valid=%t message=%q err=%v", valid, message, err)
	}
	valid, _, err = validateEBPFDiagnostics(data, protocol.SubjectConfig{Kind: protocol.SubjectEBPFTC})
	if err != nil || valid {
		t.Fatalf("TC proof unexpectedly valid: valid=%t err=%v", valid, err)
	}
}

type fakeRunner struct {
	runs   [][]string
	starts [][]string
}

func (f *fakeRunner) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	f.runs = append(f.runs, append([]string{name}, arguments...))
	return []byte(`{"probe":"ok"}`), nil
}

func (f *fakeRunner) Start(name string, arguments []string, _, _ io.Writer) (Process, error) {
	f.starts = append(f.starts, append([]string{name}, arguments...))
	return &fakeProcess{done: make(chan error, 1)}, nil
}

type fakeProcess struct {
	done   chan error
	closed bool
}

func (*fakeProcess) PID() int { return 1234 }
func (p *fakeProcess) Signal(os.Signal) error {
	if !p.closed {
		p.closed = true
		p.done <- nil
		close(p.done)
	}
	return nil
}
func (p *fakeProcess) Kill() error        { return p.Signal(os.Kill) }
func (p *fakeProcess) Done() <-chan error { return p.done }

func TestManagedEBPFDryRunLifecycle(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing API authorization")
		}
		_, _ = writer.Write([]byte(`{"ebpf":[{"tag":"benchmark-ebpf-in","state":"normal","local_enabled":true,"local_data_plane":"tc","attachments":[{"interface_name":"eth0","role":"local","mechanism":"tcx"}]}]}`))
	}))
	defer api.Close()
	binary := t.TempDir() + "/sing-box"
	if err := os.WriteFile(binary, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := protocol.Config{
		ProtocolVersion: protocol.Version, RunID: "dry-run", Subject: protocol.SubjectConfig{
			Kind: protocol.SubjectEBPFTC, SingBoxBinary: binary, OutboundInterface: "eth0", IncludeUID: []uint32{2000},
			APIListen: strings.TrimPrefix(api.URL, "http://"), APIToken: "secret",
		},
		Execution: protocol.ExecutionConfig{TemporaryDirectory: t.TempDir(), StartupTimeoutMS: 1000},
		Workload:  protocol.WorkloadConfig{Protocol: protocol.ProtocolTCP, Target: "192.0.2.1:9000"},
	}
	commands := &fakeRunner{}
	managed := New(config, commands)
	managed.FindProcesses = func([]string) ([]string, error) { return nil, nil }
	warmupDetails, _ := json.Marshal(map[string]any{
		"identity": protocol.WorkerIdentity{PID: 4321, UID: 2000},
		"workload": protocol.WorkloadResult{SocketPaths: []protocol.SocketPathEvidence{{Network: "tcp", ClientLocal: "192.0.2.1:1000", ServerObservedPeer: "192.0.2.1:2000"}}},
	})
	_, err := runner.Execute(context.Background(), managed,
		func(context.Context) (subject.WarmupEvidence, error) {
			return subject.WarmupEvidence{Valid: true, Details: warmupDetails}, nil
		},
		func(context.Context, protocol.PathProof) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(commands.runs) != 2 || len(commands.starts) != 1 {
		t.Fatalf("runs=%v starts=%v", commands.runs, commands.starts)
	}
	if commands.runs[0][1] != "tools" || commands.runs[1][1] != "check" {
		t.Fatalf("runs=%v", commands.runs)
	}
}

func TestManagedCreatesAndRemovesOnlyItsWorkerCgroup(t *testing.T) {
	root := t.TempDir()
	cgroupPath := root + "/worker"
	config := protocol.Config{
		RunID:     "cgroup-owner",
		Subject:   protocol.SubjectConfig{Kind: protocol.SubjectEBPFCgroup, CgroupPath: cgroupPath, APIListen: "127.0.0.1:9090"},
		Execution: protocol.ExecutionConfig{TemporaryDirectory: t.TempDir()},
		Workload:  protocol.WorkloadConfig{Protocol: protocol.ProtocolTCP, Target: "192.0.2.1:9000"},
	}
	managed := New(config, &fakeRunner{})
	if err := managed.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := managed.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cgroupPath); err != nil {
		t.Fatal(err)
	}
	if err := managed.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("cleanup removed the parent cgroup")
	}
	if err := managed.VerifyRestore(context.Background()); err != nil {
		t.Fatal(err)
	}
}
