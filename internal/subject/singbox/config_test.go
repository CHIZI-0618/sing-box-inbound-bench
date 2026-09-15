package singbox

import (
	"encoding/json"
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

func TestGenerateEBPFConfigs(t *testing.T) {
	for _, kind := range []protocol.SubjectKind{protocol.SubjectEBPFTC, protocol.SubjectEBPFCgroup} {
		t.Run(string(kind), func(t *testing.T) {
			config := protocol.Config{Subject: protocol.SubjectConfig{Kind: kind, IncludeUID: []uint32{2000}, APIListen: "127.0.0.1:9090", CgroupPath: "/sys/fs/cgroup/bench"}}
			content, err := GenerateConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err = json.Unmarshal(content, &decoded); err != nil {
				t.Fatal(err)
			}
			inbound := decoded["inbounds"].([]any)[0].(map[string]any)
			local := inbound["local"].(map[string]any)
			wantPlane := "tc"
			if kind == protocol.SubjectEBPFCgroup {
				wantPlane = "cgroup"
			}
			if local["data_plane"] != wantPlane || local["bypass_private_address"] != false || local["dns_mode"] != "off" {
				t.Fatalf("local=%v", local)
			}
			if kind == protocol.SubjectEBPFTC {
				if _, exists := local["cgroup_path"]; exists {
					t.Fatal("TC config contains cgroup_path")
				}
			}
		})
	}
}

func TestGenerateDirectConfig(t *testing.T) {
	config := protocol.Config{Subject: protocol.SubjectConfig{Kind: protocol.SubjectDirect, Listen: "127.0.0.1:18080", Target: "192.0.2.1:9000"}}
	content, err := GenerateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(content, &decoded); err != nil {
		t.Fatal(err)
	}
	inbound := decoded["inbounds"].([]any)[0].(map[string]any)
	if inbound["override_address"] != "192.0.2.1" || inbound["override_port"] != float64(9000) {
		t.Fatalf("inbound=%v", inbound)
	}
}
