//go:build linux || android

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	benchTCP "github.com/CHIZI-0618/sing-box-inbound-bench/internal/workload/tcp"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "worker" && os.Args[2] == "-request" {
		request, err := ReadRequest(os.Args[3])
		if err == nil {
			err = Serve(context.Background(), request, os.Stdin, os.Stdout)
		}
		if err != nil {
			_, _ = os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestServeWaitsForStartAndReturnsIdentity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (benchTCP.Server{}).Serve(ctx, listener) }()
	request := Request{ProtocolVersion: protocol.Version, RunID: "test", Workload: protocol.WorkloadConfig{
		Protocol: protocol.ProtocolTCP, Mode: protocol.ModeEcho, Target: listener.Addr().String(), PayloadBytes: 64, Requests: 1, Connections: 1, Flows: 1, TimeoutMS: 1000,
	}, CollectProof: true}
	var output bytes.Buffer
	if err = Serve(context.Background(), request, bytes.NewBufferString("start\ncollect\n"), &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var ready Ready
	var finished Finished
	var result Result
	if err = decoder.Decode(&ready); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Decode(&finished); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if ready.Type != "ready" || finished.Type != "finished" || finished.PID != ready.Identity.PID || ready.Identity.PID < 1 || result.Identity != ready.Identity || result.Workload.Counters.Operations != 1 || len(result.Workload.SocketPaths) != 1 {
		t.Fatalf("ready=%+v finished=%+v result=%+v", ready, finished, result)
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestRunProcessHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (benchTCP.Server{}).Serve(ctx, listener) }()
	request := Request{ProtocolVersion: protocol.Version, RunID: "test", Workload: protocol.WorkloadConfig{
		Protocol: protocol.ProtocolTCP, Mode: protocol.ModeEcho, Target: listener.Addr().String(), PayloadBytes: 64, Requests: 1, Connections: 1, Flows: 1, TimeoutMS: 1000,
	}, CollectProof: true}
	beforeCalled := false
	afterCalled := false
	result, err := RunProcess(context.Background(), os.Args[0], t.TempDir(), request, ProcessHooks{
		BeforeStart: func(ready Ready) error {
			beforeCalled = ready.Identity.PID > 0
			return nil
		},
		AfterWorkload: func() error {
			afterCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !beforeCalled || !afterCalled || result.Workload.Counters.Operations != 1 || len(result.Workload.SocketPaths) != 1 {
		t.Fatalf("before=%t after=%t result=%+v", beforeCalled, afterCalled, result)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
