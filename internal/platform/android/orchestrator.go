package android

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
		benchmarkAfter := adb.snapshot(restoreContext)
		if writeErr := protocol.WriteJSON(filepath.Join(result.AuditDirectory, "android-benchmark-after.json"), benchmarkAfter); writeErr != nil {
			returnErr = errors.Join(returnErr, writeErr)
		}
		if stoppedBaseline != nil {
			if restoreErr := VerifySnapshot(*stoppedBaseline, benchmarkAfter); restoreErr != nil {
				returnErr = errors.Join(returnErr, restoreErr)
			}
		} else if !serviceWasRunning {
			if restoreErr := VerifySnapshot(before, benchmarkAfter); restoreErr != nil {
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

func VerifySnapshot(before, after DeviceSnapshot) error {
	var changed []string
	for _, name := range []string{"ip4-rule", "ip6-rule", "ip4-route", "ip6-route", "iptables", "ip6tables", "nftables", "links"} {
		left, leftOK := before.Commands[name]
		right, rightOK := after.Commands[name]
		if !leftOK || !rightOK || left.Error != "" || right.Error != "" {
			continue
		}
		if normalizeSnapshot(name, left.Output) != normalizeSnapshot(name, right.Output) {
			changed = append(changed, name)
		}
	}
	if len(changed) > 0 {
		return fmt.Errorf("Android network state differs after restore: %s", strings.Join(changed, ", "))
	}
	return nil
}

func normalizeSnapshot(name, value string) string {
	if name == "nftables" || name == "links" {
		var decoded any
		if json.Unmarshal([]byte(value), &decoded) == nil {
			removeVolatileJSON(decoded)
			if canonical, err := json.Marshal(decoded); err == nil {
				return string(canonical)
			}
		}
	}
	lines := strings.Split(strings.TrimSpace(value), "\n")
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if (name == "iptables" || name == "ip6tables") && (strings.HasPrefix(line, "# Generated by ") || strings.HasPrefix(line, "# Completed on ")) {
			continue
		}
		if name == "iptables" || name == "ip6tables" {
			line = iptablesCounterPattern.ReplaceAllString(line, "[0:0]")
		}
		if name == "ip4-route" || name == "ip6-route" {
			line = routeExpiryPattern.ReplaceAllString(line, " expires <volatile>")
		}
		normalized = append(normalized, line)
	}
	return strings.Join(normalized, "\n")
}

var (
	iptablesCounterPattern = regexp.MustCompile(`\[[0-9]+:[0-9]+\]`)
	routeExpiryPattern     = regexp.MustCompile(` expires [0-9]+sec`)
)

func removeVolatileJSON(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"handle", "packets", "bytes", "stats", "stats64"} {
			delete(typed, key)
		}
		for _, child := range typed {
			removeVolatileJSON(child)
		}
	case []any:
		for _, child := range typed {
			removeVolatileJSON(child)
		}
	}
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
