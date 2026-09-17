package singbox

import (
	"context"
	"encoding/json"
	"io"
	"os"
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
	data := []byte(`{"inbounds":[{"tag":"benchmark-ebpf-in","state":"normal","localEnabled":true,"localDataPlane":"cgroup","attachments":[{"interfaceName":"/sys/fs/cgroup/bench","role":"local","mechanism":"cgroup"}],"counters":{},"udpNAT":{}}],"kernelRuntime":{"mapOccupancy":{"status":"available"}}}`)
	valid, message, err := validateEBPFDiagnostics(data, protocol.SubjectConfig{Kind: protocol.SubjectEBPFCgroup, CgroupPath: "/sys/fs/cgroup/bench"})
	if err != nil || !valid || message != "" {
		t.Fatalf("valid=%t message=%q err=%v", valid, message, err)
	}
	valid, _, err = validateEBPFDiagnostics(data, protocol.SubjectConfig{Kind: protocol.SubjectEBPFTC})
	if err != nil || valid {
		t.Fatalf("TC proof unexpectedly valid: valid=%t err=%v", valid, err)
	}
}

func TestValidateRuntimeDiagnosticsRejectsFailureDelta(t *testing.T) {
	before := []byte(`{"inbounds":[{"tag":"benchmark-ebpf-in","state":"normal","localEnabled":true,"localDataPlane":"tc","attachments":[{"interfaceName":"eth0","role":"local","mechanism":"tcx"}],"counters":{"assignmentLookupFailures":"1"},"udpNAT":{}}]}`)
	after := []byte(`{"inbounds":[{"tag":"benchmark-ebpf-in","state":"normal","localEnabled":true,"localDataPlane":"tc","attachments":[{"interfaceName":"eth0","role":"local","mechanism":"tcx"}],"counters":{"assignmentLookupFailures":"2"},"udpNAT":{}}]}`)
	managed := New(protocol.Config{Subject: protocol.SubjectConfig{Kind: protocol.SubjectEBPFTC, OutboundInterface: "eth0"}}, nil)
	if err := managed.ValidateRuntimeDiagnostics(before, after); err == nil {
		t.Fatal("accepted an eBPF failure counter increase")
	}
}

type fakeRunner struct {
	runs   [][]string
	starts [][]string
}

func (f *fakeRunner) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	f.runs = append(f.runs, append([]string{name}, arguments...))
	if len(arguments) > 0 && arguments[0] == "tools" {
		return []byte(`{"probe":"ok"}`), nil
	}
	if len(arguments) > 0 && arguments[0] == "api" {
		return []byte(`{"inbounds":[{"tag":"benchmark-ebpf-in","state":"normal","localEnabled":true,"localDataPlane":"tc","attachments":[{"interfaceName":"eth0","role":"local","mechanism":"tcx"}],"counters":{},"udpNAT":{}}]}`), nil
	}
	return nil, nil
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
	binary := t.TempDir() + "/sing-box"
	if err := os.WriteFile(binary, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := protocol.Config{
		ProtocolVersion: protocol.Version, RunID: "dry-run", Subject: protocol.SubjectConfig{
			Kind: protocol.SubjectEBPFTC, SingBoxBinary: binary, OutboundInterface: "eth0", IncludeUID: []uint32{2000},
			APIListen: "127.0.0.1:19091", APIToken: "secret",
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
	if len(commands.runs) != 4 || len(commands.starts) != 1 {
		t.Fatalf("runs=%v starts=%v", commands.runs, commands.starts)
	}
	if commands.runs[0][1] != "tools" || commands.runs[1][1] != "check" || commands.runs[2][1] != "api" || commands.runs[3][1] != "api" {
		t.Fatalf("runs=%v", commands.runs)
	}
	if got := commands.runs[2]; len(got) < 7 || got[2] != "--url" || got[4] != "--secret" || got[6] != "ebpf" {
		t.Fatalf("api command=%v", got)
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

func TestManagedDirectUDPWaitsForUDPListener(t *testing.T) {
	commands := &fakeRunner{}
	managed := New(protocol.Config{
		Subject:   protocol.SubjectConfig{Kind: protocol.SubjectDirect, Listen: "127.0.0.1:18080"},
		Execution: protocol.ExecutionConfig{StartupTimeoutMS: 1000},
		Workload:  protocol.WorkloadConfig{Protocol: protocol.ProtocolUDP},
	}, commands)
	var network string
	var port uint16
	var ipv6 bool
	managed.HasSocket = func(gotNetwork string, gotPort uint16, gotIPv6 bool) (bool, error) {
		network, port, ipv6 = gotNetwork, gotPort, gotIPv6
		return true, nil
	}
	if err := managed.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if network != "udp" || port != 18080 || ipv6 {
		t.Fatalf("listener probe network=%q port=%d ipv6=%t", network, port, ipv6)
	}
}
