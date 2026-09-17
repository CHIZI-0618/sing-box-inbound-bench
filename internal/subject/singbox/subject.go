package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/cgroup"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/netdev"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/netfilter"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

const maxArtifactBytes = 4 << 20

type Managed struct {
	Config        protocol.Config
	Runner        CommandRunner
	FindProcesses func([]string) ([]string, error)
	ReadInterface func(string) (netdev.Stats, error)
	HasSocket     func(string, uint16, bool) (bool, error)

	runDirectory string
	configPath   string
	stdout       *os.File
	stderr       *os.File
	process      Process
	processExit  error
	configHash   string
	kernelProbe  json.RawMessage
	netfilter    *netfilter.Manager
	cgroupOwned  bool
}

func New(config protocol.Config, runner CommandRunner) *Managed {
	if runner == nil {
		runner = OSCommandRunner{}
	}
	return &Managed{Config: config, Runner: runner, FindProcesses: subject.FindProcesses, ReadInterface: netdev.Read, HasSocket: netdev.HasListeningSocket}
}

func (m *Managed) Kind() protocol.SubjectKind { return m.Config.Subject.Kind }

func (m *Managed) ProcessID() int {
	if m.process == nil || m.exited() {
		return 0
	}
	return m.process.PID()
}

func (m *Managed) Preflight(ctx context.Context) error {
	if m.Config.Subject.Kind == protocol.SubjectRaw {
		return errors.New("raw does not use the sing-box subject")
	}
	info, err := os.Stat(m.Config.Subject.SingBoxBinary)
	if err != nil {
		return fmt.Errorf("sing-box binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("sing-box binary is not a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("sing-box binary is not executable")
	}
	findProcesses := m.FindProcesses
	if findProcesses == nil {
		findProcesses = subject.FindProcesses
	}
	if found, scanErr := findProcesses([]string{"sing-box"}); scanErr != nil {
		return scanErr
	} else if len(found) > 0 {
		return fmt.Errorf("another sing-box process is already running: %s", strings.Join(found, ", "))
	}
	if m.Config.Subject.Kind == protocol.SubjectRedirect || m.Config.Subject.Kind == protocol.SubjectTProxy {
		listen, parseErr := netip.ParseAddrPort(m.Config.Subject.Listen)
		if parseErr != nil {
			return parseErr
		}
		occupied, inspectErr := m.HasSocket(string(m.Config.Workload.Protocol), listen.Port(), listen.Addr().Is6())
		if inspectErr != nil {
			return fmt.Errorf("inspect transparent listener: %w", inspectErr)
		}
		if occupied {
			return fmt.Errorf("transparent listener port %d is already in use", listen.Port())
		}
	}
	if m.Config.Subject.Kind == protocol.SubjectTun || m.Config.Subject.Kind == protocol.SubjectTunAuto {
		if _, inspectErr := m.ReadInterface(m.Config.Subject.TunName); inspectErr == nil {
			return fmt.Errorf("TUN interface %s already exists", m.Config.Subject.TunName)
		} else if !errors.Is(inspectErr, os.ErrNotExist) {
			return fmt.Errorf("inspect TUN interface: %w", inspectErr)
		}
	}
	if m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
		if _, statErr := os.Stat(m.Config.Subject.CgroupPath); statErr == nil {
			return errors.New("benchmark worker cgroup already exists; refusing to adopt an unowned cgroup")
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect benchmark worker cgroup: %w", statErr)
		}
	}
	_, err = GenerateConfig(m.Config)
	if err != nil {
		return err
	}
	if m.Config.Subject.Kind == protocol.SubjectEBPFTC || m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
		plane := "tc"
		if m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
			plane = "cgroup"
		}
		target, parseErr := netip.ParseAddrPort(m.Config.Workload.Target)
		if parseErr != nil {
			return parseErr
		}
		output, probeErr := m.Runner.Run(ctx, m.Config.Subject.SingBoxBinary,
			"tools", "ebpf", "status", "--local-data-plane", plane, "--network", string(m.Config.Workload.Protocol),
			fmt.Sprintf("--ipv6=%t", target.Addr().Is6()), "--json")
		if probeErr != nil {
			return fmt.Errorf("eBPF capability probe: %w: %s", probeErr, strings.TrimSpace(string(output)))
		}
		if !json.Valid(output) {
			return errors.New("eBPF capability probe returned invalid JSON")
		}
		m.kernelProbe = bytes.TrimSpace(output)
	}
	return nil
}

func (m *Managed) Snapshot(ctx context.Context) error {
	root := m.temporaryRoot()
	runDirectory, err := ownedRunDirectory(root, m.Config.RunID)
	if err != nil {
		return err
	}
	if _, err = os.Stat(runDirectory); err == nil {
		return fmt.Errorf("run directory already exists: %s", runDirectory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.runDirectory = runDirectory
	if m.Config.Subject.Kind == protocol.SubjectRedirect || m.Config.Subject.Kind == protocol.SubjectTProxy {
		target, parseErr := netip.ParseAddrPort(m.Config.Workload.Target)
		if parseErr != nil {
			return parseErr
		}
		listen, parseErr := netip.ParseAddrPort(m.Config.Subject.Listen)
		if parseErr != nil {
			return parseErr
		}
		kind := netfilter.Redirect
		if m.Config.Subject.Kind == protocol.SubjectTProxy {
			kind = netfilter.TProxy
		}
		m.netfilter, parseErr = netfilter.New(netfilter.Config{
			Kind: kind, RunID: m.Config.RunID, Target: target, Listen: listen,
			WorkerUID: *m.Config.Execution.WorkerUID, Protocol: string(m.Config.Workload.Protocol),
			FirewallBinary: m.Config.Subject.FirewallBinary, IPBinary: m.Config.Subject.IPBinary,
			Mark: m.Config.Subject.Mark, RouteTable: m.Config.Subject.RouteTable, RulePriority: m.Config.Subject.RulePriority,
		}, m.Runner)
		if parseErr != nil {
			return parseErr
		}
		if parseErr = m.netfilter.Snapshot(ctx); parseErr != nil {
			return parseErr
		}
	}
	return nil
}

func (m *Managed) Setup(context.Context) error {
	if m.runDirectory == "" {
		return errors.New("snapshot was not completed")
	}
	if err := os.MkdirAll(filepath.Dir(m.runDirectory), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(m.runDirectory, 0o700); err != nil {
		return err
	}
	if m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
		if err := os.Mkdir(m.Config.Subject.CgroupPath, 0o755); err != nil {
			return fmt.Errorf("create benchmark worker cgroup: %w", err)
		}
		m.cgroupOwned = true
	}
	content, err := GenerateConfig(m.Config)
	if err != nil {
		return err
	}
	m.configPath = filepath.Join(m.runDirectory, "sing-box.json")
	if err = os.WriteFile(m.configPath, append(content, '\n'), 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	m.configHash = hex.EncodeToString(sum[:])
	m.stdout, err = os.OpenFile(filepath.Join(m.runDirectory, "stdout.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	m.stderr, err = os.OpenFile(filepath.Join(m.runDirectory, "stderr.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	return err
}

func (m *Managed) Start(ctx context.Context) error {
	output, err := m.Runner.Run(ctx, m.Config.Subject.SingBoxBinary, "check", "-c", m.configPath)
	if err != nil {
		return fmt.Errorf("sing-box check: %w: %s", err, strings.TrimSpace(string(output)))
	}
	arguments := []string{"run", "-c", m.configPath}
	arguments = append(arguments, m.Config.Subject.ExtraArguments...)
	m.process, err = m.Runner.Start(m.Config.Subject.SingBoxBinary, arguments, m.stdout, m.stderr)
	if err != nil {
		return err
	}
	if m.Config.Subject.Kind == protocol.SubjectDirect {
		if err = m.waitListener(ctx); err != nil {
			return err
		}
		return nil
	}
	if m.Config.Subject.Kind == protocol.SubjectRedirect || m.Config.Subject.Kind == protocol.SubjectTProxy {
		if err = m.waitTransparentListener(ctx); err != nil {
			return err
		}
		return m.netfilter.Install(ctx)
	}
	if m.Config.Subject.Kind == protocol.SubjectTun || m.Config.Subject.Kind == protocol.SubjectTunAuto {
		return m.waitTunInterface(ctx)
	}
	if err = m.waitForSurvival(ctx, 150*time.Millisecond); err != nil {
		return err
	}
	if m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
		inside, membershipErr := cgroup.ContainsPID(m.Config.Subject.CgroupPath, m.process.PID())
		if membershipErr != nil {
			return fmt.Errorf("verify sing-box cgroup isolation: %w", membershipErr)
		}
		if inside {
			return errors.New("sing-box inherited the benchmark worker cgroup")
		}
	}
	return nil
}

func (m *Managed) waitTransparentListener(ctx context.Context) error {
	listen, err := netip.ParseAddrPort(m.Config.Subject.Listen)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(m.Config.Execution.StartupTimeoutMS) * time.Millisecond)
	for {
		if m.exited() {
			return fmt.Errorf("sing-box exited during startup: %w", m.processExit)
		}
		ready, inspectErr := m.HasSocket(string(m.Config.Workload.Protocol), listen.Port(), listen.Addr().Is6())
		if inspectErr != nil {
			return fmt.Errorf("inspect transparent listener: %w", inspectErr)
		}
		if ready {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("transparent listener did not become ready")
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		}
	}
}

func (m *Managed) waitListener(ctx context.Context) error {
	deadline := time.Now().Add(time.Duration(m.Config.Execution.StartupTimeoutMS) * time.Millisecond)
	for {
		if m.exited() {
			return fmt.Errorf("sing-box exited during startup: %w", m.processExit)
		}
		connection, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", m.Config.Subject.Listen)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("listener did not become ready: %w", err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		}
	}
}

func (m *Managed) waitTunInterface(ctx context.Context) error {
	deadline := time.Now().Add(time.Duration(m.Config.Execution.StartupTimeoutMS) * time.Millisecond)
	for {
		if m.exited() {
			return fmt.Errorf("sing-box exited during startup: %w", m.processExit)
		}
		if _, err := m.ReadInterface(m.Config.Subject.TunName); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return fmt.Errorf("TUN interface did not become ready: %w", err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		}
	}
}

func (m *Managed) waitForSurvival(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case exitErr := <-m.process.Done():
		m.processExit = exitErr
		if exitErr == nil {
			m.processExit = errors.New("process exited")
		}
		return fmt.Errorf("sing-box exited during startup: %w", m.processExit)
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Managed) ObservePath(ctx context.Context) (subject.Observation, error) {
	if m.process == nil || m.exited() {
		return subject.Observation{}, errors.New("sing-box process is not running")
	}
	if m.Config.Subject.Kind == protocol.SubjectDirect {
		data, _ := json.Marshal(map[string]any{"pid": m.process.PID(), "config_sha256": m.configHash, "listener": m.Config.Subject.Listen})
		return subject.Observation{CapturedAt: time.Now(), Data: data}, nil
	}
	if m.netfilter != nil {
		data, err := m.netfilter.Observe(ctx)
		return subject.Observation{CapturedAt: time.Now(), Data: data}, err
	}
	if m.Config.Subject.Kind == protocol.SubjectTun || m.Config.Subject.Kind == protocol.SubjectTunAuto {
		return m.observeTun(ctx)
	}
	deadline := time.Now().Add(time.Duration(m.Config.Execution.StartupTimeoutMS) * time.Millisecond)
	for {
		observation, retry, err := m.observeEBPFOnce(ctx)
		if err == nil || !retry || time.Now().After(deadline) {
			return observation, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return subject.Observation{}, ctx.Err()
		}
	}
}

type tunObservation struct {
	Interface    netdev.Stats `json:"interface"`
	Backend      string       `json:"backend,omitempty"`
	BackendState string       `json:"backend_state,omitempty"`
}

func (m *Managed) observeTun(ctx context.Context) (subject.Observation, error) {
	stats, err := m.ReadInterface(m.Config.Subject.TunName)
	if err != nil {
		return subject.Observation{}, err
	}
	observation := tunObservation{Interface: stats}
	if m.Config.Subject.Kind == protocol.SubjectTunAuto {
		if output, nftErr := m.Runner.Run(ctx, "nft", "-j", "list", "table", "inet", "sing-box"); nftErr == nil && json.Valid(output) {
			observation.Backend = "nftables"
			observation.BackendState = string(bytes.TrimSpace(output))
		} else {
			firewall := m.Config.Subject.FirewallBinary
			if firewall == "" {
				firewall = "iptables"
				if strings.Contains(m.Config.Workload.Target, "[") {
					firewall = "ip6tables"
				}
			}
			var state []string
			for _, table := range []string{"nat", "mangle", "filter"} {
				output, tableErr := m.Runner.Run(ctx, firewall, "-w", "-t", table, "-S")
				if tableErr == nil && strings.Contains(string(output), "sing-box") {
					state = append(state, string(bytes.TrimSpace(output)))
				}
			}
			if len(state) == 0 {
				return subject.Observation{}, errors.New("auto_redirect backend state was not observable")
			}
			observation.Backend = "iptables"
			observation.BackendState = strings.Join(state, "\n")
		}
	}
	data, err := json.Marshal(observation)
	return subject.Observation{CapturedAt: time.Now(), Data: data}, err
}

func (m *Managed) observeEBPFOnce(ctx context.Context) (subject.Observation, bool, error) {
	arguments := []string{"api", "--url", m.Config.Subject.APIListen}
	if m.Config.Subject.APIToken != "" {
		arguments = append(arguments, "--secret", m.Config.Subject.APIToken)
	}
	arguments = append(arguments, "ebpf")
	data, err := m.Runner.Run(ctx, m.Config.Subject.SingBoxBinary, arguments...)
	if err != nil {
		return subject.Observation{}, true, fmt.Errorf("query sing-box eBPF API: %w: %s", err, bytes.TrimSpace(data))
	}
	if !json.Valid(data) {
		return subject.Observation{}, false, errors.New("eBPF diagnostics returned invalid JSON")
	}
	return subject.Observation{CapturedAt: time.Now(), Data: bytes.TrimSpace(data)}, false, nil
}

func (m *Managed) ProvePath(_ context.Context, before, after subject.Observation, warmup subject.WarmupEvidence) (protocol.PathProof, error) {
	proof := protocol.PathProof{ObservedAt: time.Now(), Before: before.Data, After: after.Data, Evidence: warmup.Details}
	if !warmup.Valid {
		proof.Error = "end-to-end warmup token failed"
		return proof, nil
	}
	if m.Config.Subject.Kind == protocol.SubjectDirect {
		proofError := subject.ValidateSocketPathEvidence(warmup.Details, true, m.Config.Execution.WorkerUID, "")
		proof.Valid = proofError == nil
		proof.Method = "server-confirmed outbound socket tuple distinct from the worker tuple through the dedicated direct listener"
		if proofError != nil {
			proof.Error = proofError.Error()
		}
		return proof, nil
	}
	if m.netfilter != nil {
		counterErr := m.netfilter.Prove(before.Data, after.Data)
		socketErr := subject.ValidateSocketPathEvidence(warmup.Details, true, m.Config.Execution.WorkerUID, "")
		proof.Method = "run-owned netfilter chain counters plus server-confirmed redirected tuple"
		proof.Valid = counterErr == nil && socketErr == nil
		if counterErr != nil || socketErr != nil {
			proof.Error = errors.Join(counterErr, socketErr).Error()
		}
		return proof, nil
	}
	if m.Config.Subject.Kind == protocol.SubjectTun || m.Config.Subject.Kind == protocol.SubjectTunAuto {
		var beforeTun, afterTun tunObservation
		decodeErr := errors.Join(json.Unmarshal(before.Data, &beforeTun), json.Unmarshal(after.Data, &afterTun))
		delta, deltaErr := netdev.Delta(beforeTun.Interface, afterTun.Interface)
		socketErr := subject.ValidateSocketPathEvidence(warmup.Details, true, m.Config.Execution.WorkerUID, "")
		activityErr := error(nil)
		if deltaErr == nil && (delta.RXPackets == 0 || delta.TXPackets == 0) {
			activityErr = errors.New("TUN RX/TX counters did not both increase")
		}
		backendErr := error(nil)
		if m.Config.Subject.Kind == protocol.SubjectTunAuto && (beforeTun.Backend == "" || afterTun.Backend == "" || beforeTun.Backend != afterTun.Backend) {
			backendErr = errors.New("auto_redirect backend was not stable across warmup")
		}
		proof.Method = "TUN RX/TX counter deltas plus server-confirmed redirected tuple"
		if m.Config.Subject.Kind == protocol.SubjectTunAuto {
			proof.Method = "active auto_redirect backend, TUN RX/TX counter deltas, and server-confirmed redirected tuple"
		}
		proof.Valid = decodeErr == nil && deltaErr == nil && activityErr == nil && backendErr == nil && socketErr == nil
		if !proof.Valid {
			proof.Error = errors.Join(decodeErr, deltaErr, activityErr, backendErr, socketErr).Error()
		}
		return proof, nil
	}
	valid, message, err := validateEBPFDiagnostics(after.Data, m.Config.Subject)
	cgroupPath := ""
	if m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
		cgroupPath = m.Config.Subject.CgroupPath
	}
	proofError := subject.ValidateSocketPathEvidence(warmup.Details, true, m.Config.Execution.WorkerUID, cgroupPath)
	proof.Method = "runtime eBPF attachment plus pre-socket worker identity and server-confirmed redirected tuple"
	proof.Valid = valid && proofError == nil
	proof.Error = message
	if proofError != nil {
		if proof.Error == "" {
			proof.Error = proofError.Error()
		} else {
			proof.Error = errors.Join(errors.New(message), proofError).Error()
		}
	}
	proof.Evidence, _ = json.Marshal(map[string]any{"warmup": json.RawMessage(warmup.Details), "kernel_probe": m.kernelProbe})
	return proof, err
}

func (m *Managed) Stop(ctx context.Context) error {
	var cleanupErr error
	if m.netfilter != nil {
		cleanupErr = m.netfilter.Cleanup(ctx)
	}
	if m.process == nil || m.exited() {
		return cleanupErr
	}
	if err := m.process.Signal(os.Interrupt); err != nil {
		if m.exited() {
			return nil
		}
		return errors.Join(cleanupErr, err)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case m.processExit = <-m.process.Done():
		return cleanupErr
	case <-timer.C:
		if err := m.process.Kill(); err != nil {
			return errors.Join(cleanupErr, err)
		}
		m.processExit = <-m.process.Done()
		return cleanupErr
	case <-ctx.Done():
		return errors.Join(cleanupErr, ctx.Err())
	}
}

func (m *Managed) Artifacts(context.Context) ([]subject.Artifact, error) {
	var errs []error
	if err := m.closeLogs(); err != nil {
		errs = append(errs, err)
	}
	redacted := m.Config
	if redacted.Subject.APIToken != "" {
		redacted.Subject.APIToken = "<redacted>"
	}
	if content, err := GenerateConfig(redacted); err != nil {
		errs = append(errs, err)
	} else {
		content = append(content, '\n')
		artifacts := []subject.Artifact{{Name: "sing-box.redacted.json", Content: content}}
		if len(m.kernelProbe) > 0 {
			artifacts = append(artifacts, subject.Artifact{Name: "kernel-probe.json", Content: append(append([]byte(nil), m.kernelProbe...), '\n')})
		}
		if m.netfilter != nil {
			if commands, commandErr := m.netfilter.Commands(); commandErr != nil {
				errs = append(errs, commandErr)
			} else {
				artifacts = append(artifacts, subject.Artifact{Name: "netfilter-commands.json", Content: append(commands, '\n')})
			}
		}
		for _, name := range []string{"stdout.log", "stderr.log"} {
			if m.runDirectory == "" {
				continue
			}
			artifact, readErr := readArtifact(filepath.Join(m.runDirectory, name), name)
			if readErr != nil {
				if !errors.Is(readErr, os.ErrNotExist) {
					errs = append(errs, readErr)
				}
				continue
			}
			artifacts = append(artifacts, artifact)
		}
		return artifacts, errors.Join(errs...)
	}
	return nil, errors.Join(errs...)
}

func readArtifact(path, name string) (subject.Artifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return subject.Artifact{}, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
	if err != nil {
		return subject.Artifact{}, err
	}
	truncated := len(content) > maxArtifactBytes
	if truncated {
		content = content[:maxArtifactBytes]
	}
	return subject.Artifact{Name: name, Content: content, Truncated: truncated}, nil
}

func (m *Managed) closeLogs() error {
	var errs []error
	for _, file := range []*os.File{m.stdout, m.stderr} {
		if file != nil {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}
	m.stdout = nil
	m.stderr = nil
	return errors.Join(errs...)
}

func (m *Managed) Cleanup(ctx context.Context) error {
	var errs []error
	if m.netfilter != nil {
		if err := m.netfilter.Cleanup(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.closeLogs(); err != nil {
		errs = append(errs, err)
	}
	if m.runDirectory != "" {
		root := m.temporaryRoot()
		expected, err := ownedRunDirectory(root, m.Config.RunID)
		if err != nil {
			errs = append(errs, err)
		} else if filepath.Clean(expected) != filepath.Clean(m.runDirectory) {
			errs = append(errs, errors.New("refusing to remove a run directory outside the owned path"))
		} else if err = os.RemoveAll(expected); err != nil {
			errs = append(errs, err)
		}
	}
	if m.cgroupOwned {
		if err := os.Remove(m.Config.Subject.CgroupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove benchmark worker cgroup: %w", err))
		} else {
			m.cgroupOwned = false
		}
	}
	return errors.Join(errs...)
}

func (m *Managed) VerifyRestore(ctx context.Context) error {
	if m.netfilter != nil {
		if err := m.netfilter.VerifyRestore(ctx); err != nil {
			return err
		}
	}
	if m.process != nil && !m.exited() {
		return errors.New("sing-box process is still running")
	}
	if m.runDirectory != "" {
		if _, err := os.Stat(m.runDirectory); err == nil {
			return errors.New("run directory remains after cleanup")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
		if _, err := os.Stat(m.Config.Subject.CgroupPath); err == nil {
			return errors.New("benchmark worker cgroup remains after cleanup")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m *Managed) temporaryRoot() string {
	if m.Config.Execution.TemporaryDirectory != "" {
		return m.Config.Execution.TemporaryDirectory
	}
	return filepath.Join(os.TempDir(), "sing-box-inbound-bench")
}

func ownedRunDirectory(root, runID string) (string, error) {
	if root == "" || runID == "" || strings.ContainsAny(runID, `/\\`) {
		return "", errors.New("invalid owned run directory")
	}
	root = filepath.Clean(root)
	if filepath.Dir(root) == root {
		return "", errors.New("temporary root cannot be a filesystem root")
	}
	runDirectory := filepath.Join(root, runID)
	relative, err := filepath.Rel(root, runDirectory)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return "", errors.New("run directory escapes temporary root")
	}
	return runDirectory, nil
}

func (m *Managed) exited() bool {
	if m.processExit != nil {
		return true
	}
	select {
	case m.processExit = <-m.process.Done():
		if m.processExit == nil {
			m.processExit = errors.New("process exited")
		}
		return true
	default:
		return false
	}
}
