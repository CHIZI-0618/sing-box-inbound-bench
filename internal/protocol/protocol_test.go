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
	content := `{"protocol_version":"inbound-bench/v1","run_id":"test","unknown":true}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unexpected error: %v", err)
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
			if _, err := ReadConfig(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}
