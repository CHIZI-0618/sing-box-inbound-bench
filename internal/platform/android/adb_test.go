package android

import (
	"context"
	"reflect"
	"testing"
)

type fakeExecutor struct{ calls [][]string }

func (f *fakeExecutor) Run(_ context.Context, arguments ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), arguments...))
	return []byte("ok"), nil
}

func TestDryRunDoesNotExecute(t *testing.T) {
	fake := &fakeExecutor{}
	plan, err := BenchmarkProcessPlan("/data/local/tmp/sing-box", "run-1", "/tmp/inbound-bench")
	if err != nil {
		t.Fatal(err)
	}
	plan.DryRun = true
	plan.Executor = fake
	if _, err = plan.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("dry-run executed %v", fake.calls)
	}
}

func TestSerialAndArgumentBoundaries(t *testing.T) {
	fake := &fakeExecutor{}
	plan := Plan{Serial: "serial-1", Executor: fake, Commands: []Command{{Arguments: []string{"shell", "id"}}}}
	if _, err := plan.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"-s", "serial-1", "shell", "id"}}
	if !reflect.DeepEqual(fake.calls, want) {
		t.Fatalf("calls=%v want=%v", fake.calls, want)
	}
}

func TestCleanupRejectsUnownedResource(t *testing.T) {
	if _, err := CleanupPlan("/data/local/tmp/sing-box", "run-1", []string{"/data/local/tmp/sing-box"}); err == nil {
		t.Fatal("accepted cleanup of parent directory")
	}
	directory, _ := RemoteRunDirectory("/data/local/tmp/sing-box", "run-1")
	plan, err := CleanupPlan("/data/local/tmp/sing-box", "run-1", []string{directory + "/file", directory})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Commands) != 2 || plan.Commands[1].Resource != directory {
		t.Fatalf("commands=%v", plan.Commands)
	}
}

func TestRemoteRunDirectoryRejectsTraversal(t *testing.T) {
	for _, runID := range []string{"../x", "x/y", ""} {
		if _, err := RemoteRunDirectory("/data/local/tmp/sing-box", runID); err == nil {
			t.Fatalf("accepted run ID %q", runID)
		}
	}
}
