package netdev

import (
	"net"
	"runtime"
	"testing"
)

func TestHasListeningSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires procfs")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	found, err := HasListeningSocket("tcp", port, false)
	if err != nil || !found {
		t.Fatalf("found=%t err=%v", found, err)
	}
}
