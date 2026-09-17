package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"protocol_version":"inbound-bench/v3","run_id":"test","unknown":true}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExplicitZeroWarmupIsPreserved(t *testing.T) {
	config := Config{Execution: ExecutionConfig{WarmupRepetitions: 0}}
	config.ApplyDefaults()
	if config.Execution.WarmupRepetitions != 0 {
		t.Fatalf("warmup=%d", config.Execution.WarmupRepetitions)
	}
}

func TestValidCgroupPathUsesDevicePOSIXSemantics(t *testing.T) {
	for _, testCase := range []struct {
		path string
		want bool
	}{
		{path: "/sys/fs/cgroup/inbound-bench", want: true},
		{path: "/sys/fs/cgroup/nested/worker", want: true},
		{path: "/sys/fs/cgroup", want: false},
		{path: "/sys/fs/cgroup/../escape", want: false},
		{path: `C:\\sys\\fs\\cgroup\\worker`, want: false},
	} {
		if got := validCgroupPath(testCase.path); got != testCase.want {
			t.Fatalf("validCgroupPath(%q)=%t, want %t", testCase.path, got, testCase.want)
		}
	}
}

func TestConfigValidationRejectsAmbiguousWorkloads(t *testing.T) {
	base := Config{
		ProtocolVersion: Version,
		RunID:           "run-1",
		Subject:         SubjectConfig{Kind: SubjectRaw},
		Workload: WorkloadConfig{Protocol: ProtocolUDP, Mode: ModeEcho, Target: "127.0.0.1:9000", PayloadBytes: 64,
			Requests: 1, Connections: 1, Flows: 1},
		Execution: ExecutionConfig{Repetitions: 1, OutputDirectory: "results"},
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.Workload.DurationMS = 1 },
		func(config *Config) { config.Workload.OfferedPPS = 1 },
		func(config *Config) { config.Workload.Requests = 0 },
	} {
		config := base
		mutate(&config)
		if err := config.Validate(); err == nil {
			t.Fatalf("ambiguous workload accepted: %+v", config.Workload)
		}
	}
}

func TestDirectTargetMustBeListener(t *testing.T) {
	config := Config{
		ProtocolVersion: Version,
		RunID:           "run-1",
		Subject:         SubjectConfig{Kind: SubjectDirect, SingBoxBinary: "sing-box", Listen: "127.0.0.1:9000", Target: "192.0.2.1:9000"},
		Workload: WorkloadConfig{Protocol: ProtocolTCP, Mode: ModeEcho, Target: "127.0.0.1:9001", PayloadBytes: 64,
			Requests: 1, Connections: 1, Flows: 1},
		Execution: ExecutionConfig{Repetitions: 1, OutputDirectory: "results"},
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "workload.target must equal subject.listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEBPFWorkerIdentityValidation(t *testing.T) {
	workerUID := uint32(2000)
	base := Config{
		ProtocolVersion: Version,
		RunID:           "run-1",
		Subject: SubjectConfig{Kind: SubjectEBPFCgroup, SingBoxBinary: "sing-box", CgroupPath: "/sys/fs/cgroup/inbound-bench",
			IncludeUID: []uint32{workerUID}, APIListen: "127.0.0.1:9090", APIToken: "secret"},
		Workload: WorkloadConfig{Protocol: ProtocolTCP, Mode: ModeEcho, Target: "192.0.2.1:9000", PayloadBytes: 64,
			Requests: 1, Connections: 1, Flows: 1},
		Execution: ExecutionConfig{Repetitions: 1, OutputDirectory: "results", WorkerUID: &workerUID},
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.Execution.WorkerUID = nil },
		func(config *Config) { config.Subject.IncludeUID = []uint32{2000, 2001} },
		func(config *Config) { config.Subject.CgroupPath = "/tmp/not-a-cgroup" },
	} {
		config := base
		mutate(&config)
		if err := config.Validate(); err == nil {
			t.Fatalf("invalid eBPF worker isolation accepted: %+v", config)
		}
	}
}

func TestSchemasAreValidJSON(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "schema", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range matches {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var schema any
		if err = json.Unmarshal(content, &schema); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	config := Config{
		ProtocolVersion: Version,
		RunID:           "run-1",
		Subject:         SubjectConfig{Kind: SubjectRaw},
		Workload: WorkloadConfig{
			Protocol:     ProtocolUDP,
			Mode:         ModePPS,
			Target:       "127.0.0.1:9000",
			PayloadBytes: 64,
			DurationMS:   1_000,
			OfferedPPS:   1_000,
			Connections:  1,
			Flows:        1,
		},
		Execution: ExecutionConfig{Repetitions: 1, OutputDirectory: "results"},
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigsValidate(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "configs", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no example configs found")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if strings.Contains(filepath.Base(path), ".example.") {
				return
			}
			var err error
			if strings.HasPrefix(filepath.Base(path), "matrix-") {
				_, err = ReadMatrixConfig(path)
			} else {
				_, err = ReadConfig(path)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
