//go:build linux && integration

package netfilter

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func TestIntegrationRedirect(t *testing.T) {
	requireRootAndTools(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:15001")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serveEcho(t, listener)
	manager, err := New(Config{
		Kind: Redirect, RunID: "integration-redirect", Target: netip.MustParseAddrPort("127.0.0.2:19090"),
		Listen: netip.MustParseAddrPort("127.0.0.1:15001"), WorkerUID: 0, Protocol: "tcp",
	}, execRunner{})
	if err != nil {
		t.Fatal(err)
	}
	runInterception(t, manager, "127.0.0.2:19090")
}

func TestIntegrationTProxy(t *testing.T) {
	requireRootAndTools(t)
	listenConfig := net.ListenConfig{Control: transparentControl}
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:15002")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serveEcho(t, listener)
	manager, err := New(Config{
		Kind: TProxy, RunID: "integration-tproxy", Target: netip.MustParseAddrPort("198.51.100.1:19090"),
		Listen: netip.MustParseAddrPort("127.0.0.1:15002"), WorkerUID: 0, Protocol: "tcp",
		Mark: 0x800000, RouteTable: 20230, RulePriority: 12000,
	}, execRunner{})
	if err != nil {
		t.Fatal(err)
	}
	runInterception(t, manager, "198.51.100.1:19090")
}

func TestIntegrationTProxyUDP(t *testing.T) {
	requireRootAndTools(t)
	listenConfig := net.ListenConfig{Control: transparentControl}
	listener, err := listenConfig.ListenPacket(context.Background(), "udp4", "127.0.0.1:15003")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	manager, err := New(Config{
		Kind: TProxy, RunID: "integration-tproxy-udp", Target: netip.MustParseAddrPort("198.51.100.2:19090"),
		Listen: netip.MustParseAddrPort("127.0.0.1:15003"), WorkerUID: 0, Protocol: "udp",
		Mark: 0x800001, RouteTable: 20231, RulePriority: 12001,
	}, execRunner{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = manager.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = manager.Install(ctx); err != nil {
		_ = manager.Cleanup(context.Background())
		t.Fatal(err)
	}
	defer func() {
		if cleanupErr := manager.Cleanup(context.Background()); cleanupErr != nil {
			t.Error(cleanupErr)
		}
	}()
	before, err := manager.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("udp4", "198.51.100.2:19090", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write([]byte("proof")); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 16)
	count, _, err := listener.ReadFrom(buffer)
	if err != nil || string(buffer[:count]) != "proof" {
		t.Fatalf("packet=%q err=%v", buffer[:count], err)
	}
	after, err := manager.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Prove(before, after); err != nil {
		t.Fatal(err)
	}
}

func transparentControl(_, _ string, connection syscall.RawConn) error {
	var controlErr error
	if err := connection.Control(func(fd uintptr) {
		controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 19, 1) // IP_TRANSPARENT
	}); err != nil {
		return err
	}
	return controlErr
}

func runInterception(t *testing.T, manager *Manager, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(ctx); err != nil {
		_ = manager.Cleanup(context.Background())
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := manager.VerifyRestore(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, chain := range manager.chains() {
			if _, err := (execRunner{}).Run(context.Background(), manager.config.FirewallBinary, "-w", "-t", manager.table(), "-S", chain); err == nil {
				t.Fatalf("owned chain %s remains", chain)
			}
		}
	}()
	before, err := manager.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Write([]byte("proof")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err = io.ReadFull(connection, buffer); err != nil || string(buffer) != "proof" {
		t.Fatalf("echo=%q err=%v", buffer, err)
	}
	_ = connection.Close()
	after, err := manager.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Prove(before, after); err != nil {
		t.Fatal(err)
	}
}

func serveEcho(t *testing.T, listener net.Listener) {
	t.Helper()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
}

func requireRootAndTools(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root in an isolated network namespace")
	}
	for _, tool := range []string{"ip", "iptables"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is unavailable", tool)
		}
	}
}
