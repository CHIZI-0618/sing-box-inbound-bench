package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const Version = "inbound-bench/v2"

type SubjectKind string

const (
	SubjectRaw        SubjectKind = "raw"
	SubjectDirect     SubjectKind = "direct"
	SubjectEBPFTC     SubjectKind = "ebpf-tc"
	SubjectEBPFCgroup SubjectKind = "ebpf-cgroup"
)

var subjectKinds = []SubjectKind{SubjectRaw, SubjectDirect, SubjectEBPFTC, SubjectEBPFCgroup}

type WorkloadProtocol string

const (
	ProtocolTCP WorkloadProtocol = "tcp"
	ProtocolUDP WorkloadProtocol = "udp"
)

type WorkloadMode string

const (
	ModeEcho         WorkloadMode = "echo"
	ModeBulkUpload   WorkloadMode = "bulk-upload"
	ModeBulkDownload WorkloadMode = "bulk-download"
	ModeShort        WorkloadMode = "short"
	ModePPS          WorkloadMode = "pps"
)

type Config struct {
	ProtocolVersion string          `json:"protocol_version"`
	RunID           string          `json:"run_id"`
	Subject         SubjectConfig   `json:"subject"`
	Workload        WorkloadConfig  `json:"workload"`
	Execution       ExecutionConfig `json:"execution"`
}

type SubjectConfig struct {
	Kind              SubjectKind `json:"kind"`
	SingBoxBinary     string      `json:"sing_box_binary,omitempty"`
	Listen            string      `json:"listen,omitempty"`
	Target            string      `json:"target,omitempty"`
	OutboundInterface string      `json:"outbound_interface,omitempty"`
	CgroupPath        string      `json:"cgroup_path,omitempty"`
	IncludeUID        []uint32    `json:"include_uid,omitempty"`
	APIListen         string      `json:"api_listen,omitempty"`
	APIToken          string      `json:"api_token,omitempty"`
	ExtraArguments    []string    `json:"extra_arguments,omitempty"`
}

type WorkloadConfig struct {
	Protocol     WorkloadProtocol `json:"protocol"`
	Mode         WorkloadMode     `json:"mode"`
	Target       string           `json:"target"`
	PayloadBytes int              `json:"payload_bytes"`
	Requests     int              `json:"requests,omitempty"`
	DurationMS   int64            `json:"duration_ms,omitempty"`
	Connections  int              `json:"connections,omitempty"`
	Flows        int              `json:"flows,omitempty"`
	OfferedPPS   int              `json:"offered_pps,omitempty"`
	TimeoutMS    int64            `json:"timeout_ms,omitempty"`
}

type ExecutionConfig struct {
	WarmupRepetitions  int     `json:"warmup_repetitions"`
	Repetitions        int     `json:"repetitions"`
	OutputDirectory    string  `json:"output_directory"`
	TemporaryDirectory string  `json:"temporary_directory,omitempty"`
	StartupTimeoutMS   int64   `json:"startup_timeout_ms,omitempty"`
	WorkerUID          *uint32 `json:"worker_uid,omitempty"`
}

type Manifest struct {
	ProtocolVersion string            `json:"protocol_version"`
	RunID           string            `json:"run_id"`
	CreatedAt       time.Time         `json:"created_at"`
	ToolVersion     string            `json:"tool_version"`
	GoVersion       string            `json:"go_version"`
	GOOS            string            `json:"goos"`
	GOARCH          string            `json:"goarch"`
	Hostname        string            `json:"hostname,omitempty"`
	Subject         SubjectKind       `json:"subject"`
	Topology        string            `json:"topology,omitempty"`
	Properties      map[string]string `json:"properties,omitempty"`
}

type PathProof struct {
	Valid      bool            `json:"valid"`
	Method     string          `json:"method"`
	ObservedAt time.Time       `json:"observed_at"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type Validity struct {
	Valid   bool     `json:"valid"`
	Reasons []string `json:"reasons,omitempty"`
}

type PhaseResult struct {
	Name       string    `json:"name"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
}

type ExecutionTrace struct {
	StartedAt       time.Time     `json:"started_at"`
	FinishedAt      time.Time     `json:"finished_at"`
	RestoreVerified bool          `json:"restore_verified"`
	Phases          []PhaseResult `json:"phases"`
}

type ArtifactRecord struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated,omitempty"`
}

type Counters struct {
	Operations      uint64 `json:"operations"`
	Failed          uint64 `json:"failed"`
	BytesSent       uint64 `json:"bytes_sent"`
	BytesReceived   uint64 `json:"bytes_received"`
	PacketsSent     uint64 `json:"packets_sent,omitempty"`
	PacketsReceived uint64 `json:"packets_received,omitempty"`
	Lost            uint64 `json:"lost,omitempty"`
	Reordered       uint64 `json:"reordered,omitempty"`
	Corrupt         uint64 `json:"corrupt,omitempty"`
}

type SocketPathEvidence struct {
	Network            string `json:"network"`
	ClientLocal        string `json:"client_local"`
	ServerObservedPeer string `json:"server_observed_peer"`
}

type WorkerIdentity struct {
	PID            int    `json:"pid"`
	UID            uint32 `json:"uid"`
	CgroupPath     string `json:"cgroup_path,omitempty"`
	CgroupVerified bool   `json:"cgroup_verified"`
}

type WorkloadTiming struct {
	StartedAt        time.Time `json:"started_at"`
	SetupDurationNS  int64     `json:"setup_duration_ns"`
	ActiveDurationNS int64     `json:"active_duration_ns"`
	DrainDurationNS  int64     `json:"drain_duration_ns"`
	FinishedAt       time.Time `json:"finished_at"`
}

type WorkloadResult struct {
	Counters    Counters             `json:"counters"`
	LatencyNS   []int64              `json:"latency_ns,omitempty"`
	SocketPaths []SocketPathEvidence `json:"socket_paths,omitempty"`
	Timing      WorkloadTiming       `json:"timing"`
}

type ResourceDelta struct {
	WallNanoseconds        int64             `json:"wall_nanoseconds"`
	ClientUserTicks        uint64            `json:"client_user_ticks,omitempty"`
	ClientSystemTicks      uint64            `json:"client_system_ticks,omitempty"`
	ClientRunNanoseconds   uint64            `json:"client_run_nanoseconds,omitempty"`
	ClientReadBytes        uint64            `json:"client_read_bytes,omitempty"`
	ClientWriteBytes       uint64            `json:"client_write_bytes,omitempty"`
	ClientRSSBytes         uint64            `json:"client_rss_bytes,omitempty"`
	SubjectUserTicks       uint64            `json:"subject_user_ticks,omitempty"`
	SubjectSystemTicks     uint64            `json:"subject_system_ticks,omitempty"`
	SubjectRunNanoseconds  uint64            `json:"subject_run_nanoseconds,omitempty"`
	SubjectReadBytes       uint64            `json:"subject_read_bytes,omitempty"`
	SubjectWriteBytes      uint64            `json:"subject_write_bytes,omitempty"`
	SubjectRSSBytes        uint64            `json:"subject_rss_bytes,omitempty"`
	SystemCPUTicks         []uint64          `json:"system_cpu_ticks,omitempty"`
	SystemSoftIRQs         map[string]uint64 `json:"system_softirqs,omitempty"`
	SystemContextSwitches  uint64            `json:"system_context_switches,omitempty"`
	SystemProcessesCreated uint64            `json:"system_processes_created,omitempty"`
}

type Repetition struct {
	ProtocolVersion string           `json:"protocol_version"`
	RunID           string           `json:"run_id"`
	Subject         SubjectKind      `json:"subject"`
	Index           int              `json:"index"`
	Warmup          bool             `json:"warmup"`
	StartedAt       time.Time        `json:"started_at"`
	DurationNS      int64            `json:"duration_ns"`
	Counters        Counters         `json:"counters"`
	LatencyNS       []int64          `json:"latency_ns,omitempty"`
	Worker          *WorkerIdentity  `json:"worker,omitempty"`
	WorkloadTiming  *WorkloadTiming  `json:"workload_timing,omitempty"`
	Resources       ResourceDelta    `json:"resources"`
	PathProof       PathProof        `json:"path_proof"`
	Validity        Validity         `json:"validity"`
	Execution       ExecutionTrace   `json:"execution"`
	Artifacts       []ArtifactRecord `json:"artifacts,omitempty"`
	Metadata        json.RawMessage  `json:"metadata,omitempty"`
}

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (c *Config) ApplyDefaults() {
	if c.ProtocolVersion == "" {
		c.ProtocolVersion = Version
	}
	if c.Workload.PayloadBytes == 0 {
		c.Workload.PayloadBytes = 64
	}
	if c.Workload.Connections == 0 {
		c.Workload.Connections = 1
	}
	if c.Workload.Flows == 0 {
		c.Workload.Flows = 1
	}
	if c.Workload.TimeoutMS == 0 {
		c.Workload.TimeoutMS = 2_000
	}
	if c.Execution.Repetitions == 0 {
		c.Execution.Repetitions = 5
	}
	if c.Execution.WarmupRepetitions == 0 {
		c.Execution.WarmupRepetitions = 1
	}
	if c.Execution.StartupTimeoutMS == 0 {
		c.Execution.StartupTimeoutMS = 10_000
	}
}

func (c Config) Validate() error {
	var errs []error
	if c.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if !runIDPattern.MatchString(c.RunID) {
		errs = append(errs, errors.New("run_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"))
	}
	if !slices.Contains(subjectKinds, c.Subject.Kind) {
		errs = append(errs, fmt.Errorf("unsupported subject %q", c.Subject.Kind))
	}
	if c.Workload.Protocol != ProtocolTCP && c.Workload.Protocol != ProtocolUDP {
		errs = append(errs, fmt.Errorf("unsupported workload protocol %q", c.Workload.Protocol))
	}
	if err := validateMode(c.Workload.Protocol, c.Workload.Mode); err != nil {
		errs = append(errs, err)
	}
	if host, _, err := net.SplitHostPort(c.Workload.Target); err != nil {
		errs = append(errs, fmt.Errorf("workload.target: %w", err))
	} else if net.ParseIP(host) == nil {
		errs = append(errs, errors.New("workload.target must use an IP literal"))
	}
	if c.Workload.PayloadBytes < 1 || c.Workload.PayloadBytes > 1<<20 {
		errs = append(errs, errors.New("payload_bytes must be between 1 and 1048576"))
	}
	if c.Workload.Protocol == ProtocolUDP && c.Workload.PayloadBytes+40 > 65_507 {
		errs = append(errs, errors.New("UDP payload plus 40-byte benchmark header exceeds 65507 bytes"))
	}
	if c.Workload.Requests < 0 || c.Workload.DurationMS < 0 || c.Workload.OfferedPPS < 0 {
		errs = append(errs, errors.New("requests, duration_ms and offered_pps cannot be negative"))
	}
	if (c.Workload.Requests == 0) == (c.Workload.DurationMS == 0) {
		errs = append(errs, errors.New("exactly one of workload.requests or workload.duration_ms is required"))
	}
	if c.Workload.Mode == ModePPS {
		if c.Workload.OfferedPPS < 1 || c.Workload.OfferedPPS > 1_000_000_000 {
			errs = append(errs, errors.New("workload.offered_pps must be between 1 and 1000000000 for UDP PPS mode"))
		}
		packetCount := uint64(max(c.Workload.Requests, 0))
		if packetCount == 0 && c.Workload.DurationMS > 0 && c.Workload.OfferedPPS > 0 {
			seconds := uint64(c.Workload.DurationMS / 1_000)
			rate := uint64(c.Workload.OfferedPPS)
			if seconds > ^uint64(0)/rate {
				packetCount = ^uint64(0)
			} else {
				packetCount = seconds*rate + uint64(c.Workload.DurationMS%1_000)*rate/1_000
			}
		}
		if c.Workload.Flows > 0 && packetCount < uint64(c.Workload.Flows) {
			errs = append(errs, fmt.Errorf("UDP PPS workload has %d packets for %d flows", packetCount, c.Workload.Flows))
		}
	} else if c.Workload.OfferedPPS != 0 {
		errs = append(errs, errors.New("workload.offered_pps is only valid for UDP PPS mode"))
	}
	if c.Workload.Connections < 1 || c.Workload.Flows < 1 {
		errs = append(errs, errors.New("connections and flows must be positive"))
	}
	if c.Execution.Repetitions < 1 || c.Execution.WarmupRepetitions < 0 {
		errs = append(errs, errors.New("repetitions must be positive and warmup_repetitions cannot be negative"))
	}
	if c.Execution.OutputDirectory == "" {
		errs = append(errs, errors.New("execution.output_directory is required"))
	}
	if c.Subject.Kind != SubjectRaw && c.Subject.SingBoxBinary == "" {
		errs = append(errs, errors.New("subject.sing_box_binary is required for non-raw subjects"))
	}
	if c.Subject.Kind == SubjectDirect {
		if _, _, err := net.SplitHostPort(c.Subject.Listen); err != nil {
			errs = append(errs, fmt.Errorf("subject.listen: %w", err))
		} else if !hostIsLoopback(c.Subject.Listen) {
			errs = append(errs, errors.New("subject.listen must use a loopback IP for the direct baseline"))
		}
		if host, _, err := net.SplitHostPort(c.Subject.Target); err != nil {
			errs = append(errs, fmt.Errorf("subject.target: %w", err))
		} else if net.ParseIP(host) == nil {
			errs = append(errs, errors.New("subject.target must use an IP literal"))
		}
		if c.Workload.Target != c.Subject.Listen {
			errs = append(errs, errors.New("workload.target must equal subject.listen for the direct baseline"))
		}
	}
	if (c.Subject.Kind == SubjectEBPFTC || c.Subject.Kind == SubjectEBPFCgroup) && len(c.Subject.IncludeUID) == 0 {
		errs = append(errs, errors.New("subject.include_uid is required for eBPF benchmark isolation"))
	}
	if c.Subject.Kind == SubjectEBPFTC && c.Subject.CgroupPath != "" {
		errs = append(errs, errors.New("subject.cgroup_path is only valid for ebpf-cgroup"))
	}
	if c.Subject.Kind == SubjectEBPFCgroup {
		if c.Subject.CgroupPath == "" || !filepath.IsAbs(c.Subject.CgroupPath) {
			errs = append(errs, errors.New("an absolute subject.cgroup_path is required for ebpf-cgroup isolation"))
		} else {
			cgroupRoot := filepath.Clean("/sys/fs/cgroup")
			cgroupPath := filepath.Clean(c.Subject.CgroupPath)
			relative, relErr := filepath.Rel(cgroupRoot, cgroupPath)
			if relErr != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				errs = append(errs, errors.New("subject.cgroup_path must name a dedicated child below /sys/fs/cgroup"))
			}
		}
		if len(c.Subject.IncludeUID) != 1 || c.Execution.WorkerUID == nil || c.Subject.IncludeUID[0] != *c.Execution.WorkerUID {
			errs = append(errs, errors.New("ebpf-cgroup requires one include_uid equal to execution.worker_uid"))
		}
	}
	if c.Subject.Kind == SubjectEBPFTC {
		if len(c.Subject.IncludeUID) != 1 || c.Execution.WorkerUID == nil || c.Subject.IncludeUID[0] != *c.Execution.WorkerUID {
			errs = append(errs, errors.New("ebpf-tc requires one include_uid equal to execution.worker_uid"))
		}
	}
	if c.Subject.Kind == SubjectEBPFTC || c.Subject.Kind == SubjectEBPFCgroup {
		if _, _, err := net.SplitHostPort(c.Subject.APIListen); err != nil {
			errs = append(errs, fmt.Errorf("subject.api_listen: %w", err))
		} else if !hostIsLoopback(c.Subject.APIListen) {
			errs = append(errs, errors.New("subject.api_listen must use a loopback IP"))
		}
		if c.Subject.APIToken == "" {
			errs = append(errs, errors.New("subject.api_token is required for eBPF diagnostics"))
		}
	}
	return errors.Join(errs...)
}

func hostIsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateMode(network WorkloadProtocol, mode WorkloadMode) error {
	switch network {
	case ProtocolTCP:
		if mode == ModeEcho || mode == ModeBulkUpload || mode == ModeBulkDownload || mode == ModeShort {
			return nil
		}
	case ProtocolUDP:
		if mode == ModeEcho || mode == ModePPS {
			return nil
		}
	}
	return fmt.Errorf("mode %q is not valid for %s", mode, network)
}

func ReadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var config Config
	if err = decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if err = ensureEOF(decoder); err != nil {
		return Config{}, err
	}
	config.ApplyDefaults()
	return config, config.Validate()
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("configuration contains multiple JSON values")
		}
		return err
	}
	return nil
}

func WriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".inbound-bench-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(value); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}
