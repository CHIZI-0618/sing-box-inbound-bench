package udp

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPEcho(t *testing.T) {
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Server{}).Serve(ctx, connection) }()
	result, latency, err := Run(context.Background(), ClientConfig{Target: connection.LocalAddr().String(), PayloadBytes: 1432, Requests: 40, Flows: 4, Timeout: time.Second, RunHash: 42})
	if err != nil {
		t.Fatal(err)
	}
	if result.Operations != 40 || len(latency) != 40 || result.Corrupt != 0 || result.Lost != 0 {
		t.Fatalf("result=%+v latency=%d", result, len(latency))
	}
	if result.BytesSent != 40*1432 || result.BytesReceived != 40*1432 {
		t.Fatalf("UDP byte counters must contain payload only: %+v", result)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRejectsCorruptPacket(t *testing.T) {
	packet := make([]byte, headerSize+64)
	build(packet, header{run: 1, flow: 2, sequence: 3})
	packet[len(packet)-1]++
	if _, valid := parse(packet); valid {
		t.Fatal("corrupt packet accepted")
	}
}

func TestUDPPOpenLoop(t *testing.T) {
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Server{}).Serve(ctx, connection) }()
	result, latency, err := Run(context.Background(), ClientConfig{Target: connection.LocalAddr().String(), Mode: "pps", PayloadBytes: 64, Requests: 100, Flows: 2, OfferedPPS: 1000, Timeout: time.Second, RunHash: 7})
	if err != nil {
		t.Fatal(err)
	}
	if result.Operations != 100 || len(latency) != 100 || result.Lost != 0 {
		t.Fatalf("result=%+v latency=%d", result, len(latency))
	}
	if result.BytesSent != 100*64 || result.BytesReceived != 100*64 {
		t.Fatalf("UDP byte counters must contain payload only: %+v", result)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPacketCount(t *testing.T) {
	for _, test := range []struct {
		name   string
		config ClientConfig
		want   int
		bad    bool
	}{
		{name: "requests", config: ClientConfig{Requests: 101, OfferedPPS: 1}, want: 101},
		{name: "duration", config: ClientConfig{Duration: 1500 * time.Millisecond, OfferedPPS: 1000}, want: 1500},
		{name: "sub-second", config: ClientConfig{Duration: 1500 * time.Microsecond, OfferedPPS: 1000}, want: 1},
		{name: "zero-rate", config: ClientConfig{Requests: 1}, bad: true},
		{name: "excessive-rate", config: ClientConfig{Requests: 1, OfferedPPS: 1_000_000_001}, bad: true},
		{name: "too-short", config: ClientConfig{Duration: time.Nanosecond, OfferedPPS: 1}, bad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := packetCount(test.config)
			if (err != nil) != test.bad || got != test.want {
				t.Fatalf("packetCount()=(%d, %v), want (%d, bad=%v)", got, err, test.want, test.bad)
			}
		})
	}
}

func TestPPSDistribution(t *testing.T) {
	for flow, want := range []int{3, 2, 2, 2, 2} {
		if got := perWorkerRequests(11, 5, flow); got != want {
			t.Fatalf("flow %d received %d packets, want %d", flow, got, want)
		}
	}
}
