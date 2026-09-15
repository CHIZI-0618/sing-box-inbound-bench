package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type generatedConfig struct {
	Log          map[string]any `json:"log"`
	Inbounds     []any          `json:"inbounds"`
	Outbounds    []any          `json:"outbounds"`
	Experimental map[string]any `json:"experimental,omitempty"`
}

func GenerateConfig(config protocol.Config) ([]byte, error) {
	outbound := map[string]any{"type": "direct", "tag": "benchmark-direct-out"}
	if config.Subject.OutboundInterface != "" {
		outbound["bind_interface"] = config.Subject.OutboundInterface
	}
	generated := generatedConfig{
		Log:       map[string]any{"disabled": true},
		Outbounds: []any{outbound},
	}
	switch config.Subject.Kind {
	case protocol.SubjectDirect:
		listenHost, listenPort, err := splitAddress(config.Subject.Listen)
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		targetHost, targetPort, err := splitAddress(config.Subject.Target)
		if err != nil {
			return nil, fmt.Errorf("target: %w", err)
		}
		generated.Inbounds = []any{map[string]any{
			"type": "direct", "tag": "benchmark-direct-in", "listen": listenHost, "listen_port": listenPort,
			"network": []string{"tcp", "udp"}, "udp_timeout": "5m", "override_address": targetHost, "override_port": targetPort,
		}}
	case protocol.SubjectEBPFTC, protocol.SubjectEBPFCgroup:
		plane := "tc"
		if config.Subject.Kind == protocol.SubjectEBPFCgroup {
			plane = "cgroup"
		}
		local := map[string]any{
			"enabled": true, "data_plane": plane, "dns_mode": "off", "ipv6": false,
			"bypass_private_address": false, "include_uid": config.Subject.IncludeUID,
		}
		if plane == "cgroup" && config.Subject.CgroupPath != "" {
			local["cgroup_path"] = config.Subject.CgroupPath
		}
		generated.Inbounds = []any{map[string]any{
			"type": "ebpf", "tag": "benchmark-ebpf-in", "network": []string{"tcp", "udp"}, "udp_timeout": "5m",
			"local": local, "shared": map[string]any{"enabled": false},
		}}
		if config.Subject.APIListen == "" {
			return nil, fmt.Errorf("api_listen is required for eBPF path proof")
		}
		generated.Experimental = map[string]any{"clash_api": map[string]any{"external_controller": config.Subject.APIListen, "secret": config.Subject.APIToken}}
	default:
		return nil, fmt.Errorf("unsupported sing-box subject %q", config.Subject.Kind)
	}
	return json.MarshalIndent(generated, "", "  ")
}

func splitAddress(address string) (string, uint16, error) {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid port %q", rawPort)
	}
	return host, uint16(port), nil
}
