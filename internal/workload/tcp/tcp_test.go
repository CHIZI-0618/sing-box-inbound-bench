package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

func TestTCPModes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Server{}).Serve(ctx, listener) }()
	for _, mode := range []protocol.WorkloadMode{protocol.ModeEcho, protocol.ModeBulkUpload, protocol.ModeBulkDownload, protocol.ModeShort} {
		t.Run(string(mode), func(t *testing.T) {
			result, latency, runErr := Run(context.Background(), ClientConfig{Target: listener.Addr().String(), Mode: mode, PayloadBytes: 4096, Requests: 20, Connections: 2, Timeout: time.Second})
			if runErr != nil {
				t.Fatal(runErr)
			}
			expectedLatency := 20
			if mode == protocol.ModeBulkUpload || mode == protocol.ModeBulkDownload {
				expectedLatency = 0
			}
			if result.Operations != 20 || len(latency) != expectedLatency || result.Failed != 0 {
				t.Fatalf("result=%+v latency=%d", result, len(latency))
			}
			if (mode == protocol.ModeEcho || mode == protocol.ModeShort || mode == protocol.ModeBulkUpload) && result.BytesSent != 20*4096 {
				t.Fatalf("bytes sent includes framing or misses payload: %d", result.BytesSent)
			}
			if (mode == protocol.ModeEcho || mode == protocol.ModeShort || mode == protocol.ModeBulkDownload) && result.BytesReceived != 20*4096 {
				t.Fatalf("bytes received includes framing or misses payload: %d", result.BytesReceived)
			}
		})
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTCPDurationBulk(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Server{}).Serve(ctx, listener) }()
	for _, mode := range []protocol.WorkloadMode{protocol.ModeBulkUpload, protocol.ModeBulkDownload} {
		t.Run(string(mode), func(t *testing.T) {
			result, latency, runErr := Run(context.Background(), ClientConfig{Target: listener.Addr().String(), Mode: mode, PayloadBytes: 16 << 10, Duration: 50 * time.Millisecond, Connections: 2, Timeout: time.Second})
			if runErr != nil {
				t.Fatal(runErr)
			}
			if result.Operations == 0 || result.Failed != 0 || len(latency) != 0 {
				t.Fatalf("result=%+v latency=%d", result, len(latency))
			}
			if mode == protocol.ModeBulkUpload && result.BytesSent != result.Operations*uint64(16<<10) {
				t.Fatalf("upload bytes are not complete payload blocks: %+v", result)
			}
			if mode == protocol.ModeBulkDownload && result.BytesReceived != result.Operations*uint64(16<<10) {
				t.Fatalf("download bytes are not complete payload blocks: %+v", result)
			}
		})
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTCPPathEvidence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Server{}).Serve(ctx, listener) }()
	result, err := RunDetailed(context.Background(), ClientConfig{Target: listener.Addr().String(), Mode: protocol.ModeEcho, PayloadBytes: 64, Requests: 1, Connections: 1, Timeout: time.Second, CollectProof: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SocketPaths) != 1 || result.SocketPaths[0].ClientLocal != result.SocketPaths[0].ServerObservedPeer {
		t.Fatalf("paths=%+v", result.SocketPaths)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTCPIdleLeavesConnectionsOpenForSampling(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Server{}).Serve(ctx, listener) }()
	result, connections, err := RunIdle(context.Background(), ClientConfig{
		Target: listener.Addr().String(), Mode: protocol.ModeIdle, Connections: 8,
		Duration: 20 * time.Millisecond, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Counters.Operations != 8 || len(connections) != 8 || result.Timing.ActiveDurationNS < int64(20*time.Millisecond) {
		t.Fatalf("result=%+v connections=%d", result, len(connections))
	}
	for _, connection := range connections {
		if err = connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	closeConnections(connections)
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
