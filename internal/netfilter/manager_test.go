package netfilter

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

type fakeRunner struct {
	commands []command
	failAt   int
	counters uint64
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.commands = append(r.commands, command{Name: name, Args: append([]string(nil), args...)})
	if r.failAt > 0 && len(r.commands) == r.failAt {
		return []byte("injected failure"), errors.New("failed")
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, " -S SBI_") {
		return []byte("No chain"), errors.New("exit 1")
	}
	if strings.Contains(joined, " rule show ") || strings.Contains(joined, " route show ") {
		return nil, nil
	}
	if strings.Contains(joined, " -L SBI_") {
		return []byte("Chain x\n pkts bytes target prot opt in out source destination\n" +
			uintString(r.counters) + " " + uintString(r.counters*64) + " ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0\n"), nil
	}
	return nil, nil
}

func uintString(value uint64) string {
	if value == 0 {
		return "0"
	}
	var result [20]byte
	index := len(result)
	for value > 0 {
		index--
		result[index] = byte('0' + value%10)
		value /= 10
	}
	return string(result[index:])
}

func testConfig(kind Kind) Config {
	return Config{
		Kind: kind, RunID: "test-run", Target: netip.MustParseAddrPort("192.0.2.1:9000"),
		Listen: netip.MustParseAddrPort("127.0.0.1:15001"), WorkerUID: 2000, Protocol: "tcp",
		Mark: 0x800000, RouteTable: 20230, RulePriority: 12000,
	}
}

func TestRedirectLifecycleUsesOnlyOwnedRules(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := New(testConfig(Redirect), runner)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = manager.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = manager.Install(ctx); err != nil {
		t.Fatal(err)
	}
	runner.counters = 2
	after, err := manager.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runner.counters = 0
	before, err := manager.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Prove(before, after); err != nil {
		t.Fatal(err)
	}
	if err = manager.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = manager.VerifyRestore(ctx); err != nil {
		t.Fatal(err)
	}
	assertNoGlobalFlush(t, runner.commands)
	if !hasCommand(runner.commands, "iptables", "-w -t nat -D OUTPUT") || !hasCommand(runner.commands, "iptables", "-w -t nat -X SBI_R_") {
		t.Fatalf("missing exact cleanup: %#v", runner.commands)
	}
}

func TestTProxyPartialFailureRollsBackSuccessfulMutations(t *testing.T) {
	baseline := &fakeRunner{}
	manager, err := New(testConfig(TProxy), baseline)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = manager.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	// Fail after route, rule and the first chain were installed.
	baseline.failAt = len(baseline.commands) + 4
	if err = manager.Install(ctx); err == nil {
		t.Fatal("expected injected failure")
	}
	baseline.failAt = 0
	if err = manager.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = manager.VerifyRestore(ctx); err != nil {
		t.Fatal(err)
	}
	assertNoGlobalFlush(t, baseline.commands)
	if !hasCommand(baseline.commands, "ip", "-4 rule del priority 12000") || !hasCommand(baseline.commands, "ip", "-4 route del local 0.0.0.0/0") {
		t.Fatalf("missing routing rollback: %#v", baseline.commands)
	}
}

func TestSnapshotRejectsExistingChain(t *testing.T) {
	runner := &existingChainRunner{}
	manager, err := New(testConfig(Redirect), runner)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Snapshot(context.Background()); err == nil {
		t.Fatal("accepted existing chain")
	}
}

type existingChainRunner struct{}

func (*existingChainRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte("exists"), nil
}

func assertNoGlobalFlush(t *testing.T, commands []command) {
	t.Helper()
	for _, item := range commands {
		for index, arg := range item.Args {
			if arg == "-F" && (index+1 == len(item.Args) || !strings.HasPrefix(item.Args[index+1], "SBI_")) {
				t.Fatalf("unsafe flush command: %#v", item)
			}
		}
	}
}

func hasCommand(commands []command, name, fragment string) bool {
	return slices.ContainsFunc(commands, func(item command) bool {
		return item.Name == name && strings.Contains(strings.Join(item.Args, " "), fragment)
	})
}
