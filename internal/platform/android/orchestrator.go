package android

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type ServiceConfig struct {
	Status          []string `json:"status"`
	RunningContains string   `json:"running_contains"`
	Stop            []string `json:"stop"`
	Start           []string `json:"start"`
}

type DeviceConfig struct {
	ProtocolVersion      string         `json:"protocol_version"`
	Serial               string         `json:"serial,omitempty"`
	ADB                  string         `json:"adb,omitempty"`
	RemoteRoot           string         `json:"remote_root"`
	BenchmarkBinary      string         `json:"benchmark_binary"`
	SingBoxBinary        string         `json:"sing_box_binary"`
	MatrixConfig         string         `json:"matrix_config"`
	LocalOutputDirectory string         `json:"local_output_directory"`
	KeepRemote           bool           `json:"keep_remote,omitempty"`
	Service              *ServiceConfig `json:"service,omitempty"`
}

type CommandResult struct {
	Arguments []string `json:"arguments"`
	Output    string   `json:"output,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type DeviceSnapshot struct {
	CapturedAt time.Time                `json:"captured_at"`
	Commands   map[string]CommandResult `json:"commands"`
}

type RunResult struct {
	RemoteDirectory string
	LocalResults    string
	AuditDirectory  string
}

func ReadDeviceConfig(filePath string) (DeviceConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return DeviceConfig{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config DeviceConfig
	if err = decoder.Decode(&config); err != nil {
		return DeviceConfig{}, err
	}
	if config.ProtocolVersion == "" {
		config.ProtocolVersion = protocol.Version
	}
	var errs []error
	if config.ProtocolVersion != protocol.Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", protocol.Version))
	}
	if config.RemoteRoot == "" || config.BenchmarkBinary == "" || config.SingBoxBinary == "" || config.MatrixConfig == "" || config.LocalOutputDirectory == "" {
		errs = append(errs, errors.New("remote_root, benchmark_binary, sing_box_binary, matrix_config and local_output_directory are required"))
	}
	for name, localPath := range map[string]string{"benchmark_binary": config.BenchmarkBinary, "sing_box_binary": config.SingBoxBinary, "matrix_config": config.MatrixConfig} {
		if info, statErr := os.Stat(localPath); statErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, statErr))
		} else if !info.Mode().IsRegular() {
			errs = append(errs, fmt.Errorf("%s must be a regular file", name))
		}
	}
	if config.Service != nil {
		if len(config.Service.Status) == 0 || config.Service.RunningContains == "" || len(config.Service.Stop) == 0 || len(config.Service.Start) == 0 {
			errs = append(errs, errors.New("service requires status, running_contains, stop and start"))
		}
		for _, command := range [][]string{config.Service.Status, config.Service.Stop, config.Service.Start} {
			if err = validateRemoteCommand(command); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return config, errors.Join(errs...)
}

func RunDevice(ctx context.Context, config DeviceConfig, executor Executor) (result RunResult, returnErr error) {
	if executor == nil {
		return result, errors.New("ADB executor is required")
	}
	matrix, err := protocol.ReadMatrixConfig(config.MatrixConfig)
	if err != nil {
		return result, err
	}
	ownedSnapshotState := snapshotOwnership(matrix)
	remoteDirectory, err := RemoteRunDirectory(config.RemoteRoot, matrix.MatrixID)
	if err != nil {
		return result, err
	}
	result.RemoteDirectory = remoteDirectory
	result.LocalResults = filepath.Join(config.LocalOutputDirectory, matrix.MatrixID)
	result.AuditDirectory = filepath.Join(config.LocalOutputDirectory, matrix.MatrixID+"-android-audit")
	if err = os.MkdirAll(result.AuditDirectory, 0o755); err != nil {
		return result, err
	}
	adb := &deviceExecutor{serial: config.Serial, executor: executor}
	uid, err := adb.shell(ctx, "id", "-u")
	if err != nil {
		return result, fmt.Errorf("verify adb root: %w", err)
	}
	if strings.TrimSpace(string(uid)) != "0" {
		return result, fmt.Errorf("ADB shell must be root, got uid %q", strings.TrimSpace(string(uid)))
	}
	before := adb.snapshot(ctx)
	if err = protocol.WriteJSON(filepath.Join(result.AuditDirectory, "android-before.json"), before); err != nil {
		return result, err
	}
	serviceWasRunning := false
	if config.Service != nil {
		status, statusErr := adb.shell(ctx, config.Service.Status...)
		var observed bool
		serviceWasRunning, observed = serviceState(status, statusErr, config.Service.RunningContains)
		if !observed {
			return result, fmt.Errorf("production service status: %w", statusErr)
		}
	}
	var stoppedBaseline *DeviceSnapshot
	defer func() {
		restoreContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		if cleanupErr := adb.cleanupOwnedProcesses(restoreContext, remoteDirectory); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
		benchmarkAfter := adb.snapshot(restoreContext)
		if writeErr := protocol.WriteJSON(filepath.Join(result.AuditDirectory, "android-benchmark-after.json"), benchmarkAfter); writeErr != nil {
			returnErr = errors.Join(returnErr, writeErr)
		}
		if stoppedBaseline != nil {
			if restoreErr := VerifySnapshot(*stoppedBaseline, benchmarkAfter, ownedSnapshotState); restoreErr != nil {
				returnErr = errors.Join(returnErr, restoreErr)
			}
		} else if !serviceWasRunning {
			if restoreErr := VerifySnapshot(before, benchmarkAfter, ownedSnapshotState); restoreErr != nil {
				returnErr = errors.Join(returnErr, restoreErr)
			}
		}
		if serviceWasRunning {
			if _, restoreErr := adb.shell(restoreContext, config.Service.Start...); restoreErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("restore production service: %w", restoreErr))
			} else if restoreErr = adb.waitService(restoreContext, config.Service, true); restoreErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("wait for production service restore: %w", restoreErr))
			}
		}
		after := adb.snapshot(restoreContext)
		if writeErr := protocol.WriteJSON(filepath.Join(result.AuditDirectory, "android-after.json"), after); writeErr != nil {
			returnErr = errors.Join(returnErr, writeErr)
		}
	}()
	if serviceWasRunning {
		if _, err = adb.shell(ctx, config.Service.Stop...); err != nil {
			return result, fmt.Errorf("stop production service: %w", err)
		}
		if err = adb.waitService(ctx, config.Service, false); err != nil {
			return result, fmt.Errorf("wait for production service to stop: %w", err)
		}
		baseline := adb.snapshot(ctx)
		stoppedBaseline = &baseline
		if err = protocol.WriteJSON(filepath.Join(result.AuditDirectory, "android-benchmark-before.json"), baseline); err != nil {
			return result, err
		}
	}
	remoteBench := path.Join(remoteDirectory, "inbound-bench")
	remoteSingBox := path.Join(remoteDirectory, "sing-box")
	remoteMatrix := path.Join(remoteDirectory, "matrix.json")
	if _, err = adb.shell(ctx, "mkdir", "-p", "--", remoteDirectory); err != nil {
		return result, err
	}
	if _, err = adb.run(ctx, "push", config.BenchmarkBinary, remoteBench); err != nil {
		return result, err
	}
	if _, err = adb.run(ctx, "push", config.SingBoxBinary, remoteSingBox); err != nil {
		return result, err
	}
	if _, err = adb.shell(ctx, "chmod", "0700", "--", remoteBench, remoteSingBox); err != nil {
		return result, err
	}
	rewriteMatrixForDevice(&matrix, remoteDirectory, remoteSingBox)
	temporary, err := os.CreateTemp("", "inbound-bench-android-matrix-*.json")
	if err != nil {
		return result, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = json.NewEncoder(temporary).Encode(matrix); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	if _, err = adb.run(ctx, "push", temporaryPath, remoteMatrix); err != nil {
		return result, err
	}
	if _, err = adb.shell(ctx, "chmod", "0600", "--", remoteMatrix); err != nil {
		return result, err
	}
	output, matrixErr := adb.shell(ctx, remoteBench, "matrix", "-config", remoteMatrix)
	_ = os.WriteFile(filepath.Join(result.AuditDirectory, "remote-stdout-stderr.log"), output, 0o600)
	if _, err = os.Stat(result.LocalResults); err == nil {
		return result, fmt.Errorf("local result directory already exists: %s", result.LocalResults)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	remoteResults := path.Join(remoteDirectory, "results", matrix.MatrixID)
	if _, err = adb.run(ctx, "pull", remoteResults, result.LocalResults); err != nil {
		return result, errors.Join(matrixErr, err)
	}
	if !config.KeepRemote {
		if _, err = adb.shell(ctx, "rm", "-rf", "--", remoteDirectory); err != nil {
			return result, fmt.Errorf("remove benchmark-owned remote directory: %w", err)
		}
	}
	if matrixErr != nil {
		return result, fmt.Errorf("remote matrix completed with invalid jobs; partial results were pulled: %w", matrixErr)
	}
	return result, nil
}

func (e *deviceExecutor) cleanupOwnedProcesses(ctx context.Context, remoteDirectory string) error {
	remoteBench := path.Join(remoteDirectory, "inbound-bench")
	remoteSingBox := path.Join(remoteDirectory, "sing-box")
	const script = `find_owned() { for process in /proc/[0-9]*; do executable=$(readlink "$process/exe" 2>/dev/null) || continue; case "$executable" in "$1"|"$2") printf '%s\n' "${process#/proc/}";; esac; done; }; pids=$(find_owned "$1" "$2"); [ -z "$pids" ] || kill -TERM $pids 2>/dev/null; attempt=0; while [ "$attempt" -lt 5 ]; do pids=$(find_owned "$1" "$2"); [ -z "$pids" ] && exit 0; sleep 1; attempt=$((attempt + 1)); done; pids=$(find_owned "$1" "$2"); [ -z "$pids" ] || kill -KILL $pids 2>/dev/null; sleep 1; [ -z "$(find_owned "$1" "$2")" ]`
	if _, err := e.shell(ctx, "sh", "-c", script, "inbound-bench-cleanup", remoteBench, remoteSingBox); err != nil {
		return fmt.Errorf("stop benchmark-owned Android processes: %w", err)
	}
	return nil
}

type deviceExecutor struct {
	serial   string
	executor Executor
}

func (e *deviceExecutor) run(ctx context.Context, arguments ...string) ([]byte, error) {
	args := make([]string, 0, len(arguments)+2)
	if e.serial != "" {
		args = append(args, "-s", e.serial)
	}
	args = append(args, arguments...)
	output, err := e.executor.Run(ctx, args...)
	if err != nil {
		return output, fmt.Errorf("adb %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (e *deviceExecutor) shell(ctx context.Context, command ...string) ([]byte, error) {
	if err := validateRemoteCommand(command); err != nil {
		return nil, err
	}
	return e.run(ctx, append([]string{"shell"}, command...)...)
}

func (e *deviceExecutor) waitService(ctx context.Context, service *ServiceConfig, running bool) error {
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		output, err := e.shell(ctx, service.Status...)
		observedRunning, observed := serviceState(output, err, service.RunningContains)
		if observed && observedRunning == running {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("service state did not converge: %w", lastErr)
			}
			return errors.New("service state did not converge")
		}
		timer := time.NewTimer(250 * time.Millisecond)
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

type exitCoder interface {
	ExitCode() int
}

func serviceState(output []byte, err error, runningContains string) (running bool, observed bool) {
	if strings.Contains(string(output), runningContains) {
		return true, true
	}
	if err == nil {
		return false, true
	}
	var status exitCoder
	if strings.TrimSpace(string(output)) != "" && errors.As(err, &status) && status.ExitCode() == 1 {
		return false, true
	}
	return false, false
}

func (e *deviceExecutor) snapshot(ctx context.Context) DeviceSnapshot {
	commands := map[string][]string{
		"uname": {"uname", "-a"}, "ip4-rule": {"ip", "-4", "rule", "show"}, "ip6-rule": {"ip", "-6", "rule", "show"},
		"ip4-route": {"ip", "-4", "route", "show", "table", "all"}, "ip6-route": {"ip", "-6", "route", "show", "table", "all"},
		"iptables": {"iptables-save"}, "ip6tables": {"ip6tables-save"}, "nftables": {"nft", "-j", "list", "ruleset"},
		"links": {"ip", "-details", "-json", "link", "show"},
	}
	result := DeviceSnapshot{CapturedAt: time.Now(), Commands: make(map[string]CommandResult, len(commands))}
	for name, command := range commands {
		output, err := e.shell(ctx, command...)
		item := CommandResult{Arguments: command, Output: string(bytes.TrimSpace(output))}
		if err != nil {
			item.Error = err.Error()
		}
		result.Commands[name] = item
	}
	return result
}

type SnapshotOwnership map[string][]string

func VerifySnapshot(before, after DeviceSnapshot, ownership SnapshotOwnership) error {
	var changed []string
	for name, markers := range ownership {
		left, leftOK := before.Commands[name]
		right, rightOK := after.Commands[name]
		if !leftOK || !rightOK || left.Error != "" || right.Error != "" {
			continue
		}
		for _, marker := range markers {
			if !strings.Contains(left.Output, marker) && strings.Contains(right.Output, marker) {
				changed = append(changed, name+":"+marker)
			}
		}
	}
	if len(changed) > 0 {
		slices.Sort(changed)
		return fmt.Errorf("benchmark-owned Android network state remains after restore: %s", strings.Join(changed, ", "))
	}
	return nil
}

func snapshotOwnership(matrix protocol.MatrixConfig) SnapshotOwnership {
	ownership := make(SnapshotOwnership)
	add := func(name string, markers ...string) {
		for _, marker := range markers {
			if marker != "" && !slices.Contains(ownership[name], marker) {
				ownership[name] = append(ownership[name], marker)
			}
		}
	}
	for _, config := range matrix.Cases {
		switch config.Subject.Kind {
		case protocol.SubjectRedirect:
			chain := fmt.Sprintf("SBI_R_%08X", crc32.ChecksumIEEE([]byte(config.RunID)))
			add("iptables", chain)
			add("ip6tables", chain)
		case protocol.SubjectTProxy:
			hash := fmt.Sprintf("%08X", crc32.ChecksumIEEE([]byte(config.RunID)))
			add("iptables", "SBI_O_"+hash, "SBI_P_"+hash)
			add("ip6tables", "SBI_O_"+hash, "SBI_P_"+hash)
			family := "ip4"
			if target, err := netip.ParseAddrPort(config.Workload.Target); err == nil && target.Addr().Is6() {
				family = "ip6"
			}
			add(family+"-rule", fmt.Sprintf("%d:", config.Subject.RulePriority))
			add(family+"-route", fmt.Sprintf(" table %d", config.Subject.RouteTable))
		case protocol.SubjectTun, protocol.SubjectTunAuto:
			add("links", `"ifname":"`+config.Subject.TunName+`"`, `"ifname": "`+config.Subject.TunName+`"`)
			add("ip4-route", "dev "+config.Subject.TunName)
			add("ip6-route", "dev "+config.Subject.TunName)
		}
	}
	return ownership
}

func rewriteMatrixForDevice(matrix *protocol.MatrixConfig, remoteDirectory, singBoxBinary string) {
	matrix.OutputDirectory = path.Join(remoteDirectory, "results")
	rewrite := func(config *protocol.Config) {
		config.Execution.OutputDirectory = path.Join(remoteDirectory, "ignored")
		config.Execution.TemporaryDirectory = path.Join(remoteDirectory, "tmp")
		if config.Subject.Kind != protocol.SubjectRaw {
			config.Subject.SingBoxBinary = singBoxBinary
		}
		if config.Subject.Kind == protocol.SubjectEBPFCgroup {
			config.Subject.CgroupPath = fmt.Sprintf("/sys/fs/cgroup/sbi-%08x", crc32.ChecksumIEEE([]byte(config.RunID)))
		}
	}
	for index := range matrix.Cases {
		rewrite(&matrix.Cases[index])
	}
	if matrix.RawControl != nil {
		rewrite(matrix.RawControl)
	}
}

func validateRemoteCommand(command []string) error {
	if len(command) == 0 || command[0] == "" {
		return errors.New("remote command is empty")
	}
	for _, argument := range command {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("remote command contains a control character")
		}
	}
	return nil
}
