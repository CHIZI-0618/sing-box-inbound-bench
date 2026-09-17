package suite

import (
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
	"strings"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type Options struct {
	MatrixID          string
	OutputDirectory   string
	SingBoxBinary     string
	Target            string
	RawTarget         string
	OutboundInterface string
	WorkerUID         uint32
	Seed              int64
	WarmupRepetitions int
	Repetitions       int
	Duration          int64
	IdleDuration      int64
	UDPPPS            int
	Preset            string
	Subjects          []protocol.SubjectKind
	Workloads         []string
}

const (
	PresetSmoke = "smoke"
	PresetCore  = "core"
	PresetFull  = "full"
)

type workloadTemplate struct {
	name   string
	config protocol.WorkloadConfig
}

func Generate(options Options) (protocol.MatrixConfig, error) {
	if options.MatrixID == "" {
		options.MatrixID = "lan-comparison"
	}
	if options.Seed == 0 {
		options.Seed = 20260915
	}
	if options.Preset == "" {
		options.Preset = PresetFull
	}
	if err := applyPresetDefaults(&options); err != nil {
		return protocol.MatrixConfig{}, err
	}
	target, err := netip.ParseAddrPort(options.Target)
	if err != nil {
		return protocol.MatrixConfig{}, fmt.Errorf("target: %w", err)
	}
	if options.OutputDirectory == "" || options.SingBoxBinary == "" || options.OutboundInterface == "" {
		return protocol.MatrixConfig{}, errors.New("output directory, sing-box binary and outbound interface are required")
	}
	rawTarget := target
	if options.RawTarget != "" {
		rawTarget, err = netip.ParseAddrPort(options.RawTarget)
		if err != nil {
			return protocol.MatrixConfig{}, fmt.Errorf("raw target: %w", err)
		}
		if rawTarget.Addr().Is6() != target.Addr().Is6() {
			return protocol.MatrixConfig{}, errors.New("target and raw target must use the same address family")
		}
	}
	templates, err := workloads(options, target.String())
	if err != nil {
		return protocol.MatrixConfig{}, err
	}
	subjects, err := selectedSubjects(options.Subjects)
	if err != nil {
		return protocol.MatrixConfig{}, err
	}
	matrix := protocol.MatrixConfig{
		ProtocolVersion: protocol.Version, MatrixID: options.MatrixID, Seed: options.Seed,
		OutputDirectory: options.OutputDirectory,
	}
	for _, kind := range subjects {
		for _, template := range templates {
			if kind == protocol.SubjectRedirect && template.config.Protocol == protocol.ProtocolUDP {
				continue
			}
			configTarget := target
			if kind == protocol.SubjectRaw {
				configTarget = rawTarget
				template.config.Target = rawTarget.String()
			}
			config := buildConfig(options, configTarget, kind, template)
			config.ApplyDefaults()
			if err = config.Validate(); err != nil {
				return protocol.MatrixConfig{}, fmt.Errorf("generated case %s: %w", config.RunID, err)
			}
			matrix.Cases = append(matrix.Cases, config)
		}
	}
	control := buildConfig(options, rawTarget, protocol.SubjectRaw, workloadTemplate{name: "control", config: protocol.WorkloadConfig{
		Protocol: protocol.ProtocolTCP, Mode: protocol.ModeBulkUpload, Target: rawTarget.String(), PayloadBytes: 64 << 10,
		DurationMS: options.Duration, Connections: 1, Flows: 1, TimeoutMS: 2_000,
	}})
	control.RunID = "raw-control"
	control.Execution.WarmupRepetitions = 0
	control.Execution.Repetitions = 1
	matrix.RawControl = &control
	if err = protocol.NormalizeAndValidateMatrix(&matrix); err != nil {
		return protocol.MatrixConfig{}, err
	}
	return matrix, nil
}

func applyPresetDefaults(options *Options) error {
	if options.WarmupRepetitions < -1 || options.Repetitions < 0 || options.Duration < 0 || options.IdleDuration < 0 || options.UDPPPS < 0 {
		return errors.New("warmups must be -1 or non-negative; repetitions, durations, and UDP PPS cannot be negative")
	}
	switch options.Preset {
	case PresetSmoke:
		if options.WarmupRepetitions == -1 {
			options.WarmupRepetitions = 0
		}
		if options.Repetitions == 0 {
			options.Repetitions = 1
		}
		if options.Duration == 0 {
			options.Duration = 1_000
		}
		if options.IdleDuration == 0 {
			options.IdleDuration = 1_000
		}
		if options.UDPPPS == 0 {
			options.UDPPPS = 10_000
		}
	case PresetCore:
		if options.WarmupRepetitions == -1 {
			options.WarmupRepetitions = 1
		}
		if options.Repetitions == 0 {
			options.Repetitions = 3
		}
		if options.Duration == 0 {
			options.Duration = 10_000
		}
		if options.IdleDuration == 0 {
			options.IdleDuration = 10_000
		}
		if options.UDPPPS == 0 {
			options.UDPPPS = 100_000
		}
	case PresetFull:
		if options.WarmupRepetitions == -1 {
			options.WarmupRepetitions = 1
		}
		if options.Repetitions == 0 {
			options.Repetitions = 5
		}
		if options.Duration == 0 {
			options.Duration = 20_000
		}
		if options.IdleDuration == 0 {
			options.IdleDuration = 10_000
		}
		if options.UDPPPS == 0 {
			options.UDPPPS = 100_000
		}
	default:
		return fmt.Errorf("unknown matrix preset %q (want smoke, core, or full)", options.Preset)
	}
	if options.WarmupRepetitions == -1 {
		options.WarmupRepetitions = 0
	}
	return nil
}

func selectedSubjects(requested []protocol.SubjectKind) ([]protocol.SubjectKind, error) {
	available := []protocol.SubjectKind{
		protocol.SubjectRaw, protocol.SubjectDirect, protocol.SubjectRedirect, protocol.SubjectTProxy,
		protocol.SubjectTun, protocol.SubjectTunAuto, protocol.SubjectEBPFTC, protocol.SubjectEBPFCgroup,
	}
	if len(requested) == 0 {
		return available, nil
	}
	wanted := make(map[protocol.SubjectKind]bool, len(requested))
	for _, kind := range requested {
		if wanted[kind] {
			return nil, fmt.Errorf("duplicate subject %q", kind)
		}
		wanted[kind] = true
	}
	var selected []protocol.SubjectKind
	for _, kind := range available {
		if wanted[kind] {
			selected = append(selected, kind)
			delete(wanted, kind)
		}
	}
	if len(wanted) > 0 {
		for kind := range wanted {
			return nil, fmt.Errorf("unknown subject %q", kind)
		}
	}
	return selected, nil
}

func workloads(options Options, target string) ([]workloadTemplate, error) {
	base := func(network protocol.WorkloadProtocol, mode protocol.WorkloadMode, payload int) protocol.WorkloadConfig {
		return protocol.WorkloadConfig{Protocol: network, Mode: mode, Target: target, PayloadBytes: payload, Connections: 1, Flows: 1, TimeoutMS: 2_000}
	}
	result := []workloadTemplate{
		{name: "standby", config: base(protocol.ProtocolTCP, protocol.ModeStandby, 1)},
		{name: "tcp-rtt", config: base(protocol.ProtocolTCP, protocol.ModeEcho, 64)},
		{name: "tcp-upload-1", config: base(protocol.ProtocolTCP, protocol.ModeBulkUpload, 64<<10)},
		{name: "tcp-upload-8", config: base(protocol.ProtocolTCP, protocol.ModeBulkUpload, 64<<10)},
		{name: "tcp-download-1", config: base(protocol.ProtocolTCP, protocol.ModeBulkDownload, 64<<10)},
		{name: "tcp-download-8", config: base(protocol.ProtocolTCP, protocol.ModeBulkDownload, 64<<10)},
		{name: "tcp-short-1", config: base(protocol.ProtocolTCP, protocol.ModeShort, 64)},
		{name: "tcp-short-32", config: base(protocol.ProtocolTCP, protocol.ModeShort, 64)},
		{name: "tcp-short-128", config: base(protocol.ProtocolTCP, protocol.ModeShort, 64)},
		{name: "udp-rtt", config: base(protocol.ProtocolUDP, protocol.ModeEcho, 64)},
		{name: "udp-rtt-unconnected", config: base(protocol.ProtocolUDP, protocol.ModeEcho, 64)},
		{name: "udp-pps-1", config: base(protocol.ProtocolUDP, protocol.ModePPS, 64)},
		{name: "udp-pps-1-unconnected", config: base(protocol.ProtocolUDP, protocol.ModePPS, 64)},
		{name: "udp-pps-64", config: base(protocol.ProtocolUDP, protocol.ModePPS, 64)},
		{name: "udp-pps-64-unconnected", config: base(protocol.ProtocolUDP, protocol.ModePPS, 64)},
		{name: "udp-mtu", config: base(protocol.ProtocolUDP, protocol.ModePPS, 1432)},
		{name: "udp-churn", config: base(protocol.ProtocolUDP, protocol.ModeEcho, 64)},
	}
	for _, connections := range []int{1, 250, 500, 750, 1000} {
		config := base(protocol.ProtocolTCP, protocol.ModeIdle, 1)
		config.Connections = connections
		config.DurationMS = options.IdleDuration
		result = append(result, workloadTemplate{name: fmt.Sprintf("tcp-idle-%d", connections), config: config})
	}
	for index := range result {
		config := &result[index].config
		if strings.HasSuffix(result[index].name, "-unconnected") {
			config.UDPSocketMode = protocol.UDPSocketUnconnected
		}
		switch config.Mode {
		case protocol.ModeEcho:
			if result[index].name == "udp-churn" {
				config.Requests = 1000
				config.Flows = 1000
			} else {
				config.Requests = 20_000
			}
		case protocol.ModeShort:
			config.Requests = 20_000
			suffix := result[index].name[strings.LastIndexByte(result[index].name, '-')+1:]
			_, _ = fmt.Sscan(suffix, &config.Connections)
		case protocol.ModeBulkUpload, protocol.ModeBulkDownload:
			config.DurationMS = options.Duration
			if strings.HasSuffix(result[index].name, "-8") {
				config.Connections = 8
			}
		case protocol.ModePPS:
			config.DurationMS = options.Duration
			config.OfferedPPS = options.UDPPPS
			if strings.HasPrefix(result[index].name, "udp-pps-64") {
				config.Flows = 64
			}
		case protocol.ModeStandby:
			config.DurationMS = options.IdleDuration
		}
	}
	selectedNames := options.Workloads
	if len(selectedNames) == 0 {
		switch options.Preset {
		case PresetSmoke:
			selectedNames = []string{"tcp-rtt", "udp-rtt", "udp-rtt-unconnected"}
		case PresetCore:
			selectedNames = []string{
				"standby", "tcp-rtt", "tcp-upload-1", "tcp-upload-8", "tcp-download-1", "tcp-download-8", "tcp-short-32",
				"tcp-idle-1", "tcp-idle-500", "udp-rtt", "udp-rtt-unconnected", "udp-pps-1", "udp-pps-64",
				"udp-pps-64-unconnected", "udp-churn",
			}
		case PresetFull:
			selectedNames = make([]string, 0, len(result))
			for _, template := range result {
				selectedNames = append(selectedNames, template.name)
			}
		}
	}
	available := make(map[string]workloadTemplate, len(result))
	for _, template := range result {
		available[template.name] = template
	}
	selected := make([]workloadTemplate, 0, len(selectedNames))
	seen := make(map[string]bool, len(selectedNames))
	for _, name := range selectedNames {
		if seen[name] {
			return nil, fmt.Errorf("duplicate workload %q", name)
		}
		seen[name] = true
		template, exists := available[name]
		if !exists {
			return nil, fmt.Errorf("unknown workload %q", name)
		}
		if options.Preset == PresetSmoke {
			template.config.Requests = min(template.config.Requests, 64)
		}
		selected = append(selected, template)
	}
	return selected, nil
}

func buildConfig(options Options, target netip.AddrPort, kind protocol.SubjectKind, workload workloadTemplate) protocol.Config {
	uid := options.WorkerUID
	runID := fmt.Sprintf("%s-%s", kind, workload.name)
	config := protocol.Config{
		ProtocolVersion: protocol.Version, RunID: runID,
		Subject:  protocol.SubjectConfig{Kind: kind, OutboundInterface: options.OutboundInterface},
		Workload: workload.config,
		Execution: protocol.ExecutionConfig{
			WarmupRepetitions: options.WarmupRepetitions, Repetitions: options.Repetitions,
			OutputDirectory: options.OutputDirectory, WorkerUID: &uid,
		},
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	tunAddress := []string{"172.31.255.1/30"}
	if target.Addr().Is6() {
		loopback = netip.IPv6Loopback()
		tunAddress = []string{"fd00:7362:6962::1/126"}
	}
	if kind != protocol.SubjectRaw {
		config.Subject.SingBoxBinary = options.SingBoxBinary
		config.Subject.APIListen = netip.AddrPortFrom(loopback, 19091).String()
		config.Subject.APIToken = "benchmark-" + options.MatrixID
	}
	switch kind {
	case protocol.SubjectRaw:
		config.Subject.OutboundInterface = ""
	case protocol.SubjectDirect:
		config.Subject.Listen = netip.AddrPortFrom(loopback, 18080).String()
		config.Subject.Target = target.String()
		config.Workload.Target = config.Subject.Listen
	case protocol.SubjectRedirect:
		config.Subject.Listen = netip.AddrPortFrom(loopback, 15001).String()
	case protocol.SubjectTProxy:
		config.Subject.Listen = netip.AddrPortFrom(loopback, 15002).String()
	case protocol.SubjectTun, protocol.SubjectTunAuto:
		config.Subject.TunAddress = tunAddress
		config.Subject.MTU = 1500
	case protocol.SubjectEBPFTC, protocol.SubjectEBPFCgroup:
		config.Subject.IncludeUID = []uint32{options.WorkerUID}
		if kind == protocol.SubjectEBPFCgroup {
			config.Subject.CgroupPath = fmt.Sprintf("/sys/fs/cgroup/sbi-%08x", crc32.ChecksumIEEE([]byte(runID)))
		}
	}
	return config
}
