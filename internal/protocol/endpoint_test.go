package protocol

import (
	"net"
	"testing"
)

func TestEndpointEncoding(t *testing.T) {
	for _, value := range []string{"192.0.2.1:1234", "[2001:db8::1]:65535"} {
		address, err := net.ResolveTCPAddr("tcp", value)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeEndpoint(address)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeEndpoint(encoded)
		if err != nil || decoded != value {
			t.Fatalf("DecodeEndpoint()=(%q, %v), want %q", decoded, err, value)
		}
	}
}
