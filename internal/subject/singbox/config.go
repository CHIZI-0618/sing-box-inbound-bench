package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type generatedConfig struct {
	Log       map[string]any `json:"log"`
	Inbounds  []any          `json:"inbounds"`
	Outbounds []any          `json:"outbounds"`
	Services  []any          `json:"services,omitempty"`
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
			"network": []string{string(config.Workload.Protocol)}, "udp_timeout": "5m", "override_address": targetHost, "override_port": targetPort,
		}}
	case protocol.SubjectRedirect, protocol.SubjectTProxy:
		listenHost, listenPort, err := splitAddress(config.Subject.Listen)
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		inboundType := "redirect"
		if config.Subject.Kind == protocol.SubjectTProxy {
			inboundType = "tproxy"
		}
		inbound := map[string]any{
			"type": inboundType, "tag": "benchmark-" + inboundType + "-in",
			"listen": listenHost, "listen_port": listenPort,
			"network": []string{string(config.Workload.Protocol)},
		}
		if config.Workload.Protocol == protocol.ProtocolUDP {
			inbound["udp_timeout"] = "5m"
			inbound["udp_mapping"] = "endpoint_independent"
			inbound["udp_filtering"] = "endpoint_independent"
			inbound["udp_nat_max"] = 1024
		}
		generated.Inbounds = []any{inbound}
	case protocol.SubjectTun, protocol.SubjectTunAuto:
		target, err := netip.ParseAddrPort(config.Workload.Target)
		if err != nil {
			return nil, fmt.Errorf("workload target: %w", err)
		}
		bits := 32
		if target.Addr().Is6() {
			bits = 128
		}
		generated.Inbounds = []any{map[string]any{
			"type": "tun", "tag": "benchmark-tun-in", "interface_name": config.Subject.TunName,
			"address": config.Subject.TunAddress, "mtu": config.Subject.MTU,
			"auto_route": true, "auto_redirect": config.Subject.Kind == protocol.SubjectTunAuto,
			"include_uid":   []uint32{*config.Execution.WorkerUID},
			"route_address": []string{netip.PrefixFrom(target.Addr(), bits).String()},
			"udp_timeout":   "5m", "udp_mapping": "endpoint_independent",
			"udp_filtering": "endpoint_independent", "udp_nat_max": 1024,
		}}
	case protocol.SubjectEBPFTC, protocol.SubjectEBPFCgroup:
		target, err := netip.ParseAddrPort(config.Workload.Target)
		if err != nil {
			return nil, fmt.Errorf("workload target: %w", err)
		}
		plane := "tc"
		if config.Subject.Kind == protocol.SubjectEBPFCgroup {
			plane = "cgroup"
		}
		local := map[string]any{
			"enabled": true, "data_plane": plane, "dns_mode": "off", "ipv6": target.Addr().Is6(),
			"bypass_private_address": false, "include_uid": config.Subject.IncludeUID,
		}
		if plane == "cgroup" && config.Subject.CgroupPath != "" {
			local["cgroup_path"] = config.Subject.CgroupPath
		}
		generated.Inbounds = []any{map[string]any{
			"type": "ebpf", "tag": "benchmark-ebpf-in", "network": []string{string(config.Workload.Protocol)}, "udp_timeout": "5m",
			"local": local, "shared": map[string]any{"enabled": false},
		}}
		if config.Subject.APIListen == "" {
			return nil, fmt.Errorf("api_listen is required for eBPF path proof")
		}
	default:
		return nil, fmt.Errorf("unsupported sing-box subject %q", config.Subject.Kind)
	}
	if config.Subject.APIListen != "" {
		apiHost, apiPort, err := splitAddress(config.Subject.APIListen)
		if err != nil {
			return nil, fmt.Errorf("api_listen: %w", err)
		}
		generated.Services = []any{map[string]any{
			"type": "api", "tag": "benchmark-api", "listen": apiHost, "listen_port": apiPort,
			"secret": config.Subject.APIToken,
		}}
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
