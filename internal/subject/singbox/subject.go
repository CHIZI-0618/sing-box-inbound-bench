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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
)

type Managed struct {
	Config        protocol.Config
	Runner        CommandRunner
	FindProcesses func([]string) ([]string, error)

	runDirectory string
	configPath   string
	stdout       *os.File
	stderr       *os.File
	process      Process
	processExit  error
	configHash   string
	kernelProbe  json.RawMessage
	httpClient   *http.Client
}

func New(config protocol.Config, runner CommandRunner) *Managed {
	if runner == nil {
		runner = OSCommandRunner{}
	}
	return &Managed{Config: config, Runner: runner, FindProcesses: subject.FindProcesses, httpClient: &http.Client{Timeout: 2 * time.Second}}
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
	_, err = GenerateConfig(m.Config)
	if err != nil {
		return err
	}
	if m.Config.Subject.Kind == protocol.SubjectEBPFTC || m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
		plane := "tc"
		if m.Config.Subject.Kind == protocol.SubjectEBPFCgroup {
			plane = "cgroup"
		}
		output, probeErr := m.Runner.Run(ctx, m.Config.Subject.SingBoxBinary,
			"tools", "ebpf", "status", "--local-data-plane", plane, "--network", "tcp,udp", "--ipv6=false", "--json")
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

func (m *Managed) Snapshot(context.Context) error {
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
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case exitErr := <-m.process.Done():
		m.processExit = exitErr
		if exitErr == nil {
			return errors.New("sing-box exited during startup")
		}
		return fmt.Errorf("sing-box exited during startup: %w", exitErr)
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

func (m *Managed) observeEBPFOnce(ctx context.Context) (subject.Observation, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+m.Config.Subject.APIListen+"/ebpf/", nil)
	if err != nil {
		return subject.Observation{}, false, err
	}
	if m.Config.Subject.APIToken != "" {
		request.Header.Set("Authorization", "Bearer "+m.Config.Subject.APIToken)
	}
	response, err := m.httpClient.Do(request)
	if err != nil {
		return subject.Observation{}, true, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return subject.Observation{}, false, fmt.Errorf("eBPF diagnostics returned %s: %s", response.Status, bytes.TrimSpace(body))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return subject.Observation{}, false, err
	}
	if !json.Valid(data) {
		return subject.Observation{}, false, errors.New("eBPF diagnostics returned invalid JSON")
	}
	return subject.Observation{CapturedAt: time.Now(), Data: data}, false, nil
}

func (m *Managed) ProvePath(_ context.Context, before, after subject.Observation, warmup subject.WarmupEvidence) (protocol.PathProof, error) {
	proof := protocol.PathProof{ObservedAt: time.Now(), Before: before.Data, After: after.Data, Evidence: warmup.Details}
	if !warmup.Valid {
		proof.Error = "end-to-end warmup token failed"
		return proof, nil
	}
	if m.Config.Subject.Kind == protocol.SubjectDirect {
		proof.Valid = true
		proof.Method = "checksum-validated framed exchange through a dedicated direct listener while the managed process remained alive"
		return proof, nil
	}
	valid, message, err := validateEBPFDiagnostics(after.Data, m.Config.Subject)
	proof.Method = "runtime eBPF diagnostics attachment plus isolated-UID end-to-end token"
	proof.Valid = valid
	proof.Error = message
	proof.Evidence, _ = json.Marshal(map[string]any{"warmup": json.RawMessage(warmup.Details), "kernel_probe": m.kernelProbe})
	return proof, err
}

func (m *Managed) Stop(ctx context.Context) error {
	if m.process == nil || m.exited() {
		return nil
	}
	if err := m.process.Signal(os.Interrupt); err != nil {
		if m.exited() {
			return nil
		}
		return err
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case m.processExit = <-m.process.Done():
		return nil
	case <-timer.C:
		if err := m.process.Kill(); err != nil {
			return err
		}
		m.processExit = <-m.process.Done()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Managed) Cleanup(context.Context) error {
	var errs []error
	for _, file := range []*os.File{m.stdout, m.stderr} {
		if file != nil {
			if err := file.Close(); err != nil {
				errs = append(errs, err)
			}
		}
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
	return errors.Join(errs...)
}

func (m *Managed) VerifyRestore(context.Context) error {
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

type diagnosticsEnvelope struct {
	EBPF []struct {
		Tag            string `json:"tag"`
		State          string `json:"state"`
		LocalEnabled   bool   `json:"local_enabled"`
		LocalDataPlane string `json:"local_data_plane"`
		Attachments    []struct {
			InterfaceName string `json:"interface_name"`
			Role          string `json:"role"`
			Mechanism     string `json:"mechanism"`
		} `json:"attachments"`
	} `json:"ebpf"`
}

func validateEBPFDiagnostics(data []byte, config protocol.SubjectConfig) (bool, string, error) {
	var diagnostics diagnosticsEnvelope
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		return false, "", err
	}
	wantPlane := "tc"
	if config.Kind == protocol.SubjectEBPFCgroup {
		wantPlane = "cgroup"
	}
	for _, inbound := range diagnostics.EBPF {
		if inbound.Tag != "benchmark-ebpf-in" {
			continue
		}
		if inbound.State != "normal" || !inbound.LocalEnabled || inbound.LocalDataPlane != wantPlane {
			return false, fmt.Sprintf("runtime state=%s local=%t plane=%s", inbound.State, inbound.LocalEnabled, inbound.LocalDataPlane), nil
		}
		for _, attachment := range inbound.Attachments {
			if attachment.Role != "local" {
				continue
			}
			if wantPlane == "cgroup" {
				if attachment.Mechanism == "cgroup" && filepath.Clean(attachment.InterfaceName) == filepath.Clean(config.CgroupPath) {
					return true, "", nil
				}
				continue
			}
			if attachment.Mechanism != "" && attachment.Mechanism != "cgroup" && (config.OutboundInterface == "" || attachment.InterfaceName == config.OutboundInterface) {
				return true, "", nil
			}
		}
		return false, "no matching local attachment", nil
	}
	return false, "benchmark eBPF inbound missing from diagnostics", nil
}
