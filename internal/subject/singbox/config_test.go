package singbox

import (
	"encoding/json"
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

func TestGenerateEBPFConfigs(t *testing.T) {
	for _, kind := range []protocol.SubjectKind{protocol.SubjectEBPFTC, protocol.SubjectEBPFCgroup} {
		t.Run(string(kind), func(t *testing.T) {
			config := protocol.Config{Subject: protocol.SubjectConfig{Kind: kind, IncludeUID: []uint32{2000}, APIListen: "127.0.0.1:9090", CgroupPath: "/sys/fs/cgroup/bench"}, Workload: protocol.WorkloadConfig{Protocol: protocol.ProtocolTCP, Target: "192.0.2.1:9000"}}
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
			network := inbound["network"].([]any)
			if len(network) != 1 || network[0] != "tcp" {
				t.Fatalf("network=%v", network)
			}
			if kind == protocol.SubjectEBPFTC {
				if _, exists := local["cgroup_path"]; exists {
					t.Fatal("TC config contains cgroup_path")
				}
			}
			services := decoded["services"].([]any)
			if len(services) != 1 {
				t.Fatalf("services=%v", services)
			}
			api := services[0].(map[string]any)
			if api["type"] != "api" || api["listen"] != "127.0.0.1" || api["listen_port"] != float64(9090) {
				t.Fatalf("api=%v", api)
			}
			if _, exists := decoded["experimental"]; exists {
				t.Fatal("eBPF benchmark config still contains experimental API configuration")
			}
		})
	}
}

func TestGenerateDirectConfig(t *testing.T) {
	config := protocol.Config{Subject: protocol.SubjectConfig{Kind: protocol.SubjectDirect, Listen: "127.0.0.1:18080", Target: "192.0.2.1:9000", APIListen: "127.0.0.1:9090", APIToken: "secret"}, Workload: protocol.WorkloadConfig{Protocol: protocol.ProtocolTCP}}
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
	services := decoded["services"].([]any)
	if len(services) != 1 || services[0].(map[string]any)["type"] != "api" {
		t.Fatalf("services=%v", services)
	}
}

func TestGenerateRedirectAndTProxyConfigs(t *testing.T) {
	for _, kind := range []protocol.SubjectKind{protocol.SubjectRedirect, protocol.SubjectTProxy} {
		t.Run(string(kind), func(t *testing.T) {
			config := protocol.Config{
				Subject:  protocol.SubjectConfig{Kind: kind, Listen: "127.0.0.1:15001"},
				Workload: protocol.WorkloadConfig{Protocol: protocol.ProtocolTCP},
			}
			content, err := GenerateConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			var decoded generatedConfig
			if err = json.Unmarshal(content, &decoded); err != nil {
				t.Fatal(err)
			}
			inbound := decoded.Inbounds[0].(map[string]any)
			if inbound["type"] != string(kind) || inbound["listen_port"] != float64(15001) {
				t.Fatalf("inbound=%v", inbound)
			}
			_, hasNetwork := inbound["network"]
			if hasNetwork != (kind == protocol.SubjectTProxy) {
				t.Fatalf("network field presence=%v inbound=%v", hasNetwork, inbound)
			}
		})
	}
}

func TestGenerateTunConfigs(t *testing.T) {
	uid := uint32(2000)
	for _, kind := range []protocol.SubjectKind{protocol.SubjectTun, protocol.SubjectTunAuto} {
		t.Run(string(kind), func(t *testing.T) {
			config := protocol.Config{
				Subject:  protocol.SubjectConfig{Kind: kind, TunName: "sbi0", TunAddress: []string{"172.31.255.1/30"}, MTU: 1500},
				Workload: protocol.WorkloadConfig{Target: "192.0.2.1:9000"}, Execution: protocol.ExecutionConfig{WorkerUID: &uid},
			}
			content, err := GenerateConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			var decoded generatedConfig
			if err = json.Unmarshal(content, &decoded); err != nil {
				t.Fatal(err)
			}
			inbound := decoded.Inbounds[0].(map[string]any)
			if inbound["auto_redirect"] != (kind == protocol.SubjectTunAuto) {
				t.Fatalf("inbound=%v", inbound)
			}
			routes := inbound["route_address"].([]any)
			if len(routes) != 1 || routes[0] != "192.0.2.1/32" {
				t.Fatalf("routes=%v", routes)
			}
		})
	}
}

func TestGenerateEBPFIPv6Config(t *testing.T) {
	config := protocol.Config{
		Subject:  protocol.SubjectConfig{Kind: protocol.SubjectEBPFTC, APIListen: "[::1]:9090"},
		Workload: protocol.WorkloadConfig{Protocol: protocol.ProtocolUDP, Target: "[2001:db8::1]:9000"},
	}
	content, err := GenerateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(content, &decoded); err != nil {
		t.Fatal(err)
	}
	local := decoded["inbounds"].([]any)[0].(map[string]any)["local"].(map[string]any)
	if local["ipv6"] != true {
		t.Fatalf("local=%v", local)
	}
}
