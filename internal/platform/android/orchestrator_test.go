package android

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type orchestrationExecutor struct {
	calls      [][]string
	running    bool
	generation int
}

type statusExitError struct{ code int }

func (e statusExitError) Error() string { return "exit status" }
func (e statusExitError) ExitCode() int { return e.code }

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
		return []byte("stopped\n"), statusExitError{code: 1}
	case joined == "shell /manager stop":
		e.running = false
		return nil, nil
	case joined == "shell /manager start":
		e.running = true
		e.generation++
		return nil, nil
	case joined == "shell ip -details -json link show":
		if e.running {
			return []byte(fmt.Sprintf(`[{"ifname":"wlan0"},{"ifname":"sbt%d"}]`, e.generation)), nil
		}
		return []byte(`[{"ifname":"wlan0"}]`), nil
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
	cleanupIndex := findCallContaining(executor.calls, "inbound-bench-cleanup")
	startIndex := findCall(executor.calls, "shell /manager start")
	if cleanupIndex < 0 || startIndex < 0 || cleanupIndex > startIndex {
		t.Fatalf("benchmark cleanup must run before production restore: calls=%v", executor.calls)
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
	before := DeviceSnapshot{Commands: map[string]CommandResult{"ip4-rule": {Output: "external one"}}}
	after := DeviceSnapshot{Commands: map[string]CommandResult{"ip4-rule": {Output: "external two\n12000: from all lookup 20230"}}}
	if err := VerifySnapshot(before, after, SnapshotOwnership{"ip4-rule": {"12000:"}}); err == nil {
		t.Fatal("accepted changed state")
	}
}

func TestVerifySnapshotIgnoresUnownedStateChanges(t *testing.T) {
	before := DeviceSnapshot{Commands: map[string]CommandResult{"ip4-rule": {Output: "rmnet_data3"}}}
	after := DeviceSnapshot{Commands: map[string]CommandResult{"ip4-rule": {Output: "rmnet_data2"}}}
	if err := VerifySnapshot(before, after, SnapshotOwnership{"ip4-rule": {"12000:"}}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySnapshotIgnoresVolatileCountersAndTimers(t *testing.T) {
	before := DeviceSnapshot{Commands: map[string]CommandResult{
		"ip6-route": {Output: "default via fe80::1 dev wlan0 expires 120sec pref medium"},
		"iptables":  {Output: "# Generated by iptables-save on now\n:OUTPUT ACCEPT [10:20]\n# Completed on now"},
		"links":     {Output: `[{"ifname":"wlan0","mtu":1500,"stats64":{"rx":{"packets":10,"bytes":20}}}]`},
	}}
	after := DeviceSnapshot{Commands: map[string]CommandResult{
		"ip6-route": {Output: "default via fe80::1 dev wlan0 expires 110sec pref medium"},
		"iptables":  {Output: "# Generated by iptables-save on later\n:OUTPUT ACCEPT [30:40]\n# Completed on later"},
		"links":     {Output: `[{"ifname":"wlan0","mtu":1500,"stats64":{"rx":{"packets":30,"bytes":40}}}]`},
	}}
	if err := VerifySnapshot(before, after, SnapshotOwnership{"ip6-route": {"sbi0"}, "iptables": {"SBI_R_OWNED"}, "links": {`"ifname":"sbi0"`}}); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotOwnershipCoversRunScopedResources(t *testing.T) {
	matrix := protocol.MatrixConfig{Cases: []protocol.Config{
		{RunID: "redirect", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRedirect}},
		{RunID: "tproxy", Subject: protocol.SubjectConfig{Kind: protocol.SubjectTProxy, RulePriority: 12000, RouteTable: 20230}, Workload: protocol.WorkloadConfig{Target: "192.0.2.1:9000"}},
		{RunID: "tun", Subject: protocol.SubjectConfig{Kind: protocol.SubjectTun, TunName: "sbi12345678"}},
	}}
	ownership := snapshotOwnership(matrix)
	for name, want := range map[string]string{
		"iptables": "SBI_R_", "ip4-rule": "12000:", "ip4-route": "table 20230", "links": "sbi12345678",
	} {
		if !slices.ContainsFunc(ownership[name], func(marker string) bool { return strings.Contains(marker, want) }) {
			t.Fatalf("ownership[%s]=%v does not contain %q", name, ownership[name], want)
		}
	}
}

func TestServiceStateAcceptsExplicitStoppedStatusWithExitOne(t *testing.T) {
	running, observed := serviceState([]byte("sing-box service stopped\n"), statusExitError{code: 1}, "running")
	if running || !observed {
		t.Fatalf("running=%t observed=%t", running, observed)
	}
	if _, observed = serviceState([]byte("manager: not found\n"), statusExitError{code: 127}, "running"); observed {
		t.Fatal("accepted a missing status command as stopped")
	}
}

func TestQuoteShellArgumentPreservesCleanupScript(t *testing.T) {
	quoted := quoteShellArgument(`printf '%s\n' "$1"`)
	if quoted != `'printf '\''%s\n'\'' "$1"'` {
		t.Fatalf("quoted=%s", quoted)
	}
}

func TestAndroidTargetTranslationInstallAndCleanup(t *testing.T) {
	matrix := protocol.MatrixConfig{
		MatrixID:   "translated",
		RawControl: &protocol.Config{Workload: protocol.WorkloadConfig{Target: "10.212.17.63:19090"}},
		Cases: []protocol.Config{
			{RunID: "raw", Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}, Workload: protocol.WorkloadConfig{Target: "10.212.17.63:19090"}},
			{RunID: "auto", Subject: protocol.SubjectConfig{Kind: protocol.SubjectTunAuto}, Workload: protocol.WorkloadConfig{Target: "198.18.0.1:19090"}},
		},
	}
	translation, err := newAndroidTargetTranslation(matrix, TargetTranslationConfig{
		VirtualTarget: "198.18.0.1:19090", PhysicalTarget: "10.212.17.63:19090",
		DirectMark: 0x200000, DirectMarkMask: 0xe00000,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := &orchestrationExecutor{}
	adb := &deviceExecutor{executor: executor}
	if err = translation.Install(context.Background(), adb); err != nil {
		t.Fatal(err)
	}
	if err = translation.Cleanup(context.Background(), adb); err != nil {
		t.Fatal(err)
	}
	joined := make([]string, len(executor.calls))
	for index, call := range executor.calls {
		joined[index] = strings.Join(call, " ")
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		"-m owner --uid-owner 0 -j DNAT --to-destination 10.212.17.63:19090",
		"-m mark --mark 0x200000/0xe00000 -j DNAT --to-destination 10.212.17.63:19090",
		"-I OUTPUT 1 -j " + translation.chain,
		"-D OUTPUT -j " + translation.chain,
		"-F " + translation.chain,
		"-X " + translation.chain,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("commands do not contain %q:\n%s", want, all)
		}
	}
	if translation.chainCreated || translation.jumpCreated {
		t.Fatalf("translation still marked active: %+v", translation)
	}
}

func TestAndroidTargetTranslationRejectsMismatchedMatrix(t *testing.T) {
	_, err := newAndroidTargetTranslation(protocol.MatrixConfig{
		MatrixID: "bad", Cases: []protocol.Config{{
			RunID: "auto", Subject: protocol.SubjectConfig{Kind: protocol.SubjectTunAuto},
			Workload: protocol.WorkloadConfig{Target: "10.212.17.63:19090"},
		}},
	}, TargetTranslationConfig{
		VirtualTarget: "198.18.0.1:19090", PhysicalTarget: "10.212.17.63:19090",
		DirectMark: 0x200000, DirectMarkMask: 0xe00000,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err=%v", err)
	}
}

func containsCall(calls [][]string, want string) bool {
	return slices.ContainsFunc(calls, func(call []string) bool { return strings.Join(call, " ") == want })
}

func findCall(calls [][]string, want string) int {
	return slices.IndexFunc(calls, func(call []string) bool { return strings.Join(call, " ") == want })
}

func findCallContaining(calls [][]string, want string) int {
	return slices.IndexFunc(calls, func(call []string) bool { return strings.Contains(strings.Join(call, " "), want) })
}
