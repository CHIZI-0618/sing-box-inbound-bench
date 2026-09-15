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
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
