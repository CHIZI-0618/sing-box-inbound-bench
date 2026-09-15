package suite

import (
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

func TestGenerateCompleteMatrix(t *testing.T) {
	matrix, err := Generate(Options{
		MatrixID: "test", OutputDirectory: "results", SingBoxBinary: "/tmp/sing-box",
		Target: "192.0.2.2:19090", OutboundInterface: "eth0", WorkerUID: 2000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if matrix.RawControl == nil || len(matrix.Cases) != 139 {
		t.Fatalf("cases=%d raw=%v", len(matrix.Cases), matrix.RawControl != nil)
	}
	kinds := make(map[protocol.SubjectKind]bool)
	for _, config := range matrix.Cases {
		kinds[config.Subject.Kind] = true
		if err = config.Validate(); err != nil {
			t.Fatalf("%s: %v", config.RunID, err)
		}
		if config.Subject.Kind == protocol.SubjectRedirect && config.Workload.Protocol == protocol.ProtocolUDP {
			t.Fatal("generated an unsupported redirect UDP case")
		}
	}
	if len(kinds) != 8 {
		t.Fatalf("kinds=%v", kinds)
	}
}

func TestGenerateRejectsInvalidMatrixID(t *testing.T) {
	_, err := Generate(Options{
		MatrixID: "../escape", OutputDirectory: "results", SingBoxBinary: "/tmp/sing-box",
		Target: "192.0.2.2:19090", OutboundInterface: "eth0", WorkerUID: 2000,
	})
	if err == nil {
		t.Fatal("accepted invalid matrix ID")
	}
}
