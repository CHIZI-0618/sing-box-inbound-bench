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
			if result.Operations != 20 || len(latency) != 20 || result.Failed != 0 {
				t.Fatalf("result=%+v latency=%d", result, len(latency))
			}
		})
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
