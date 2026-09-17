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
	if matrix.RawControl == nil || len(matrix.Cases) != 168 {
		t.Fatalf("cases=%d raw=%v", len(matrix.Cases), matrix.RawControl != nil)
	}
	kinds := make(map[protocol.SubjectKind]bool)
	for _, config := range matrix.Cases {
		kinds[config.Subject.Kind] = true
		if config.Subject.Kind != protocol.SubjectRaw && (config.Subject.APIListen == "" || config.Subject.APIToken == "") {
			t.Fatalf("%s is missing the uniform API service", config.RunID)
		}
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

func TestGeneratePresetMatrices(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		wantCases       int
		wantRepetitions int
		wantWarmups     int
	}{
		{name: PresetSmoke, wantCases: 22, wantRepetitions: 1, wantWarmups: 0},
		{name: PresetCore, wantCases: 114, wantRepetitions: 3, wantWarmups: 1},
		{name: PresetFull, wantCases: 168, wantRepetitions: 5, wantWarmups: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			matrix, err := Generate(Options{
				MatrixID: "test", OutputDirectory: "results", SingBoxBinary: "/tmp/sing-box",
				Target: "192.0.2.2:19090", OutboundInterface: "eth0", WorkerUID: 2000,
				Preset: testCase.name, WarmupRepetitions: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(matrix.Cases) != testCase.wantCases {
				t.Fatalf("cases=%d want=%d", len(matrix.Cases), testCase.wantCases)
			}
			for _, config := range matrix.Cases {
				if config.Execution.Repetitions != testCase.wantRepetitions || config.Execution.WarmupRepetitions != testCase.wantWarmups {
					t.Fatalf("%s repetitions=%d warmups=%d", config.RunID, config.Execution.Repetitions, config.Execution.WarmupRepetitions)
				}
			}
		})
	}
}

func TestGenerateFiltersSubjectsAndWorkloads(t *testing.T) {
	matrix, err := Generate(Options{
		MatrixID: "test", OutputDirectory: "results", SingBoxBinary: "/tmp/sing-box",
		Target: "192.0.2.2:19090", OutboundInterface: "eth0", WorkerUID: 2000,
		Preset: PresetFull, Subjects: []protocol.SubjectKind{protocol.SubjectEBPFTC, protocol.SubjectEBPFCgroup},
		Workloads: []string{"tcp-rtt", "udp-rtt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(matrix.Cases) != 4 {
		t.Fatalf("cases=%d", len(matrix.Cases))
	}
	for _, config := range matrix.Cases {
		if config.Subject.Kind != protocol.SubjectEBPFTC && config.Subject.Kind != protocol.SubjectEBPFCgroup {
			t.Fatalf("unexpected subject %s", config.Subject.Kind)
		}
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

func TestGenerateUsesPhysicalTargetForRawCases(t *testing.T) {
	matrix, err := Generate(Options{
		MatrixID: "translated", OutputDirectory: "results", SingBoxBinary: "/tmp/sing-box",
		Target: "198.18.0.1:19090", RawTarget: "10.212.17.63:19090", OutboundInterface: "wlan0", WorkerUID: 2000,
		Preset: PresetSmoke, Subjects: []protocol.SubjectKind{protocol.SubjectRaw, protocol.SubjectTunAuto}, Workloads: []string{"udp-rtt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if matrix.RawControl.Workload.Target != "10.212.17.63:19090" || matrix.Cases[0].Workload.Target != "10.212.17.63:19090" || matrix.Cases[1].Workload.Target != "198.18.0.1:19090" {
		t.Fatalf("control=%s raw=%s translated=%s", matrix.RawControl.Workload.Target, matrix.Cases[0].Workload.Target, matrix.Cases[1].Workload.Target)
	}
}
