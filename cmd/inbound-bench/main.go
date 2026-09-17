package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/metrics"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/netdev"
	benchAndroid "github.com/CHIZI-0618/sing-box-inbound-bench/internal/platform/android"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/report"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/runner"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject/raw"
	benchSingBox "github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject/singbox"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/suite"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/worker"
	benchTCP "github.com/CHIZI-0618/sing-box-inbound-bench/internal/workload/tcp"
	benchUDP "github.com/CHIZI-0618/sing-box-inbound-bench/internal/workload/udp"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "inbound-bench:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: inbound-bench <run|matrix|summarize|generate-matrix|android-run|tcp-server|udp-server> [options]")
	}
	switch arguments[0] {
	case "run":
		flags := flag.NewFlagSet("run", flag.ContinueOnError)
		configPath := flags.String("config", "", "benchmark JSON configuration")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if *configPath == "" {
			return errors.New("run requires -config")
		}
		return runBenchmark(*configPath)
	case "matrix":
		flags := flag.NewFlagSet("matrix", flag.ContinueOnError)
		configPath := flags.String("config", "", "benchmark matrix JSON configuration")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if *configPath == "" {
			return errors.New("matrix requires -config")
		}
		return runMatrix(*configPath)
	case "summarize":
		flags := flag.NewFlagSet("summarize", flag.ContinueOnError)
		configPath := flags.String("config", "", "benchmark matrix JSON configuration")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if *configPath == "" {
			return errors.New("summarize requires -config")
		}
		matrix, err := protocol.ReadMatrixConfig(*configPath)
		if err != nil {
			return err
		}
		return summarizeMatrix(matrix)
	case "generate-matrix":
		flags := flag.NewFlagSet("generate-matrix", flag.ContinueOnError)
		output := flags.String("output", "matrix.json", "generated matrix path")
		matrixID := flags.String("matrix-id", "lan-comparison", "matrix identifier")
		results := flags.String("results", "results", "result directory")
		singBox := flags.String("sing-box", "", "sing-box binary path on the benchmark device")
		target := flags.String("target", "", "TCP/UDP benchmark server IP:port")
		rawTarget := flags.String("raw-target", "", "physical server IP:port for raw cases when target translation is used")
		outboundInterface := flags.String("interface", "", "physical benchmark interface")
		workerUID := flags.Uint("worker-uid", 2000, "dedicated benchmark worker UID")
		seed := flags.Int64("seed", 20260915, "randomization seed")
		preset := flags.String("preset", suite.PresetFull, "matrix preset: smoke, core, or full")
		subjects := flags.String("subjects", "", "comma-separated subject filter")
		workloads := flags.String("workloads", "", "comma-separated workload filter")
		warmups := flags.Int("warmups", -1, "warmup repetitions per case (-1 uses preset default)")
		repetitions := flags.Int("repetitions", 0, "measured repetitions per case (0 uses preset default)")
		duration := flags.Int64("duration-ms", 0, "bulk and UDP PPS duration (0 uses preset default)")
		idleDuration := flags.Int64("idle-duration-ms", 0, "idle TCP residence duration (0 uses preset default)")
		udpPPS := flags.Int("udp-pps", 0, "total offered UDP packets per second (0 uses preset default)")
		cooldown := flags.Int64("cooldown-ms", 1_000, "delay between matrix jobs; UDP PPS jobs also require a raw health probe")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if *workerUID > uint(^uint32(0)) {
			return errors.New("worker UID exceeds uint32")
		}
		matrix, err := suite.Generate(suite.Options{
			MatrixID: *matrixID, OutputDirectory: *results, SingBoxBinary: *singBox, Target: *target, RawTarget: *rawTarget,
			OutboundInterface: *outboundInterface, WorkerUID: uint32(*workerUID), Seed: *seed,
			WarmupRepetitions: *warmups, Repetitions: *repetitions, Duration: *duration,
			IdleDuration: *idleDuration, UDPPPS: *udpPPS, CooldownMS: *cooldown, Preset: *preset,
			Subjects: parseSubjectList(*subjects), Workloads: splitCommaList(*workloads),
		})
		if err != nil {
			return err
		}
		return protocol.WriteJSON(*output, matrix)
	case "android-run":
		flags := flag.NewFlagSet("android-run", flag.ContinueOnError)
		configPath := flags.String("config", "", "Android orchestration JSON configuration")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if *configPath == "" {
			return errors.New("android-run requires -config")
		}
		config, err := benchAndroid.ReadDeviceConfig(*configPath)
		if err != nil {
			return err
		}
		_, err = benchAndroid.RunDevice(signalContext(), config, benchAndroid.OSExecutor{Binary: config.ADB})
		return err
	case "tcp-server":
		flags := flag.NewFlagSet("tcp-server", flag.ContinueOnError)
		listen := flags.String("listen", "0.0.0.0:19090", "listen address")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, listener.Addr())
		return (benchTCP.Server{}).Serve(signalContext(), listener)
	case "udp-server":
		flags := flag.NewFlagSet("udp-server", flag.ContinueOnError)
		listen := flags.String("listen", "0.0.0.0:19090", "listen address")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		connection, err := net.ListenPacket("udp", *listen)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, connection.LocalAddr())
		return (benchUDP.Server{}).Serve(signalContext(), connection)
	case "worker":
		flags := flag.NewFlagSet("worker", flag.ContinueOnError)
		requestPath := flags.String("request", "", "internal worker request")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if *requestPath == "" {
			return errors.New("worker requires -request")
		}
		request, err := worker.ReadRequest(*requestPath)
		if err != nil {
			return err
		}
		return worker.Serve(signalContext(), request, os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func splitCommaList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var result []string
	for _, item := range strings.Split(value, ",") {
		result = append(result, strings.TrimSpace(item))
	}
	return result
}

func parseSubjectList(value string) []protocol.SubjectKind {
	items := splitCommaList(value)
	result := make([]protocol.SubjectKind, len(items))
	for index, item := range items {
		result[index] = protocol.SubjectKind(item)
	}
	return result
}

func runBenchmark(configPath string) error {
	config, err := protocol.ReadConfig(configPath)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(config.Execution.OutputDirectory, 0o755); err != nil {
		return err
	}
	resultDirectory := filepath.Join(config.Execution.OutputDirectory, config.RunID)
	if err = os.Mkdir(resultDirectory, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("result directory already exists: %s", resultDirectory)
		}
		return err
	}
	if err = writeRunMetadata(resultDirectory, config); err != nil {
		return err
	}
	runContext, stopSignals := signal.NotifyContext(context.Background(), benchmarkSignals()...)
	defer stopSignals()
	total := config.Execution.WarmupRepetitions + config.Execution.Repetitions
	for index := 0; index < total; index++ {
		warmupRepetition := index < config.Execution.WarmupRepetitions
		name := repetitionName(index, config.Execution.WarmupRepetitions)
		if _, err = executeRepetition(runContext, config, resultDirectory, index, warmupRepetition, name); err != nil {
			return fmt.Errorf("repetition %d: %w", index, err)
		}
	}
	return nil
}

func writeRunMetadata(resultDirectory string, config protocol.Config) error {
	properties := map[string]string{
		"workload_protocol": string(config.Workload.Protocol), "workload_mode": string(config.Workload.Mode),
		"target": config.Workload.Target,
	}
	if config.Subject.OutboundInterface != "" {
		properties["outbound_interface"] = config.Subject.OutboundInterface
	}
	if executable, executableErr := os.Executable(); executableErr == nil {
		if digest, hashErr := hashFile(executable); hashErr == nil {
			properties["benchmark_binary_sha256"] = digest
		}
	}
	if config.Subject.Kind != protocol.SubjectRaw {
		digest, hashErr := hashFile(config.Subject.SingBoxBinary)
		if hashErr != nil {
			return fmt.Errorf("hash sing-box binary: %w", hashErr)
		}
		properties["sing_box_binary_sha256"] = digest
		if output, versionErr := exec.Command(config.Subject.SingBoxBinary, "version").CombinedOutput(); versionErr == nil {
			properties["sing_box_version"] = strings.TrimSpace(string(output))
		}
	}
	if kernel, readErr := os.ReadFile("/proc/sys/kernel/osrelease"); readErr == nil {
		properties["kernel_release"] = strings.TrimSpace(string(kernel))
	}
	manifest := protocol.Manifest{
		ProtocolVersion: protocol.Version, RunID: config.RunID, CreatedAt: time.Now(), ToolVersion: buildVersion(),
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Subject: config.Subject.Kind,
		Topology: "local transparent client to external benchmark server", Properties: properties,
	}
	if err := protocol.WriteJSON(filepath.Join(resultDirectory, "manifest.json"), manifest); err != nil {
		return err
	}
	redacted := config
	if redacted.Subject.APIToken != "" {
		redacted.Subject.APIToken = "<redacted>"
	}
	return protocol.WriteJSON(filepath.Join(resultDirectory, "config.json"), redacted)
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func executeRepetition(runContext context.Context, config protocol.Config, resultDirectory string, index int, warmupRepetition bool, name string) (protocol.Repetition, error) {
	selected := makeSubject(config)
	var repetition protocol.Repetition
	runReport, executeErr := runner.Execute(runContext, selected,
		func(ctx context.Context) (subject.WarmupEvidence, error) { return runWarmup(ctx, config, index) },
		func(ctx context.Context, proof protocol.PathProof) error {
			result, measureErr := measure(ctx, config, selected, index, warmupRepetition, proof)
			repetition = result
			return measureErr
		})
	if repetition.ProtocolVersion == "" {
		repetition = failedRepetition(config, index, warmupRepetition, runReport)
	}
	repetition.Execution = runReport.Trace
	if repetition.PathProof.ObservedAt.IsZero() {
		repetition.PathProof = runReport.PathProof
	}
	artifactRecords, artifactErr := writeArtifacts(resultDirectory, config.Subject.Kind, strings.TrimSuffix(name, ".json"), runReport.Artifacts)
	repetition.Artifacts = artifactRecords
	executeErr = errors.Join(executeErr, artifactErr)
	if executeErr != nil {
		repetition.Validity.Valid = false
		repetition.Validity.Reasons = append(repetition.Validity.Reasons, executeErr.Error())
	}
	if writeErr := protocol.WriteJSON(filepath.Join(resultDirectory, string(config.Subject.Kind), name), repetition); writeErr != nil {
		return repetition, errors.Join(executeErr, writeErr)
	}
	return repetition, executeErr
}

func repetitionName(index, warmups int) string {
	if index < warmups {
		return fmt.Sprintf("warmup-%03d.json", index)
	}
	return fmt.Sprintf("rep-%03d.json", index-warmups)
}

func runMatrix(configPath string) error {
	matrix, err := protocol.ReadMatrixConfig(configPath)
	if err != nil {
		return err
	}
	root := filepath.Join(matrix.OutputDirectory, matrix.MatrixID)
	if _, statErr := os.Stat(root); statErr == nil && !matrix.Resume {
		return fmt.Errorf("matrix result directory already exists: %s (set resume=true to continue)", root)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err = os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	redacted := matrix
	redactConfig := func(config *protocol.Config) {
		if config != nil && config.Subject.APIToken != "" {
			config.Subject.APIToken = "<redacted>"
		}
	}
	for index := range redacted.Cases {
		redactConfig(&redacted.Cases[index])
	}
	redactConfig(redacted.RawControl)
	redacted.Resume = false
	matrixPath := filepath.Join(root, "matrix.json")
	if matrix.Resume {
		if existing, readErr := os.ReadFile(matrixPath); readErr == nil {
			var stored protocol.MatrixConfig
			if decodeErr := json.Unmarshal(existing, &stored); decodeErr != nil {
				return fmt.Errorf("stored matrix configuration is invalid: %w", decodeErr)
			}
			stored.Resume = false
			storedJSON, _ := json.Marshal(stored)
			incomingJSON, _ := json.Marshal(redacted)
			if !slices.Equal(storedJSON, incomingJSON) {
				return errors.New("resume configuration does not match the stored matrix")
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
	}
	if err = protocol.WriteJSON(matrixPath, redacted); err != nil {
		return err
	}
	for _, config := range matrix.Cases {
		caseRoot := filepath.Join(root, "cases", config.RunID)
		if err = os.MkdirAll(caseRoot, 0o755); err != nil {
			return err
		}
		if _, statErr := os.Stat(filepath.Join(caseRoot, "manifest.json")); errors.Is(statErr, os.ErrNotExist) {
			if err = writeRunMetadata(caseRoot, config); err != nil {
				return err
			}
		} else if statErr != nil {
			return statErr
		}
	}
	state := buildMatrixState(root, matrix)
	if err = protocol.WriteJSON(filepath.Join(root, "state.json"), state); err != nil {
		return err
	}
	runContext, stopSignals := signal.NotifyContext(context.Background(), benchmarkSignals()...)
	defer stopSignals()
	var runErrors []error
	for index := range state.Jobs {
		job := &state.Jobs[index]
		resultPath := filepath.Join(root, filepath.FromSlash(job.Result))
		if existing, decodeErr := protocol.DecodeRepetition(resultPath); decodeErr == nil {
			job.Complete = true
			job.Valid = existing.Validity.Valid
			continue
		} else if !errors.Is(decodeErr, os.ErrNotExist) {
			return fmt.Errorf("resume result %s is unreadable: %w", job.Result, decodeErr)
		}
		config, caseIndex, configErr := matrixJobConfig(matrix, *job)
		if configErr != nil {
			return configErr
		}
		resultDirectory := filepath.Dir(filepath.Dir(resultPath))
		name := filepath.Base(resultPath)
		repetition, executeErr := executeRepetition(runContext, config, resultDirectory, caseIndex, job.Warmup, name)
		job.Complete = true
		job.Valid = repetition.Validity.Valid
		if executeErr != nil {
			job.Error = executeErr.Error()
			runErrors = append(runErrors, fmt.Errorf("%s: %w", job.ID, executeErr))
		}
		if job.Control == "" {
			if cooldownErr := waitContext(runContext, time.Duration(matrix.CooldownMS)*time.Millisecond); cooldownErr != nil {
				job.Error = errors.Join(executeErr, cooldownErr).Error()
				runErrors = append(runErrors, fmt.Errorf("%s cooldown: %w", job.ID, cooldownErr))
			}
		}
		if runContext.Err() == nil && job.Control == "" && config.Workload.Mode == protocol.ModePPS && matrix.RawControl != nil {
			var recoveryErr error
			job.Recovery, recoveryErr = runMatrixRecoveryProbe(runContext, matrix)
			if recoveryErr != nil {
				job.Error = errors.Join(executeErr, recoveryErr).Error()
				runErrors = append(runErrors, fmt.Errorf("%s recovery: %w", job.ID, recoveryErr))
			}
		}
		if err = protocol.WriteJSON(filepath.Join(root, "state.json"), state); err != nil {
			return errors.Join(errors.Join(runErrors...), err)
		}
		if runContext.Err() != nil {
			return errors.Join(errors.Join(runErrors...), runContext.Err())
		}
		if job.Recovery != nil && !job.Recovery.Valid {
			return errors.Join(runErrors...)
		}
	}
	if err = protocol.WriteJSON(filepath.Join(root, "state.json"), state); err != nil {
		return errors.Join(errors.Join(runErrors...), err)
	}
	if err = summarizeMatrix(matrix); err != nil {
		runErrors = append(runErrors, err)
	}
	return errors.Join(runErrors...)
}

const (
	matrixRecoveryAttempts = 5
	matrixRecoveryInterval = time.Second
	matrixRecoveryTimeout  = 6 * time.Second
)

func runMatrixRecoveryProbe(ctx context.Context, matrix protocol.MatrixConfig) (*protocol.MatrixRecovery, error) {
	recovery := &protocol.MatrixRecovery{StartedAt: time.Now()}
	defer func() { recovery.FinishedAt = time.Now() }()
	request := matrixRecoveryRequest(*matrix.RawControl)
	var lastErr error
	for attempt := 1; attempt <= matrixRecoveryAttempts; attempt++ {
		recovery.Attempts = attempt
		attemptContext, cancel := context.WithTimeout(ctx, matrixRecoveryTimeout)
		result, probeErr := worker.RunProcess(attemptContext, "", worker.TemporaryRoot(matrix.RawControl.Execution.TemporaryDirectory), request, worker.ProcessHooks{})
		cancel()
		recovery.Counters = result.Workload.Counters
		counters := result.Workload.Counters
		if probeErr == nil && counters.Operations == 8 && counters.Failed == 0 && counters.Lost == 0 && counters.Corrupt == 0 {
			recovery.Valid = true
			recovery.Error = ""
			return recovery, nil
		}
		lastErr = errors.Join(probeErr, fmt.Errorf("raw UDP health probe received %d/8 operations (failed=%d lost=%d corrupt=%d)", counters.Operations, counters.Failed, counters.Lost, counters.Corrupt))
		if attempt < matrixRecoveryAttempts {
			if waitErr := waitContext(ctx, matrixRecoveryInterval); waitErr != nil {
				lastErr = errors.Join(lastErr, waitErr)
				break
			}
		}
	}
	recovery.Error = lastErr.Error()
	return recovery, fmt.Errorf("network did not recover after UDP PPS workload: %w", lastErr)
}

func matrixRecoveryRequest(rawControl protocol.Config) worker.Request {
	return worker.Request{
		ProtocolVersion: protocol.Version,
		RunID:           "matrix-recovery",
		Workload: protocol.WorkloadConfig{
			Protocol: protocol.ProtocolUDP, Mode: protocol.ModeEcho, Target: rawControl.Workload.Target,
			PayloadBytes: 64, Requests: 8, Connections: 1, Flows: 1, TimeoutMS: 500,
		},
		WorkerUID: rawControl.Execution.WorkerUID,
	}
}

func waitContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func buildMatrixState(root string, matrix protocol.MatrixConfig) protocol.MatrixState {
	state := protocol.MatrixState{ProtocolVersion: protocol.Version, MatrixID: matrix.MatrixID, Seed: matrix.Seed}
	blocks := 0
	for _, config := range matrix.Cases {
		blocks = max(blocks, config.Execution.WarmupRepetitions+config.Execution.Repetitions)
	}
	for block := 0; block < blocks; block++ {
		if matrix.RawControl != nil {
			state.Jobs = append(state.Jobs, controlJob(root, matrix, block, "before"))
		}
		indices := make([]int, 0, len(matrix.Cases))
		for index, config := range matrix.Cases {
			if block < config.Execution.WarmupRepetitions+config.Execution.Repetitions {
				indices = append(indices, index)
			}
		}
		sort.Slice(indices, func(left, right int) bool {
			return matrixOrder(matrix.Seed, block, matrix.Cases[indices[left]].RunID) < matrixOrder(matrix.Seed, block, matrix.Cases[indices[right]].RunID)
		})
		for _, index := range indices {
			config := matrix.Cases[index]
			name := repetitionName(block, config.Execution.WarmupRepetitions)
			relative := filepath.ToSlash(filepath.Join("cases", config.RunID, string(config.Subject.Kind), name))
			state.Jobs = append(state.Jobs, protocol.MatrixJob{
				ID: fmt.Sprintf("%s-block-%03d", config.RunID, block), CaseID: config.RunID,
				Subject: config.Subject.Kind, Block: block, Warmup: block < config.Execution.WarmupRepetitions, Result: relative,
			})
		}
		if matrix.RawControl != nil {
			state.Jobs = append(state.Jobs, controlJob(root, matrix, block, "after"))
		}
	}
	return state
}

func controlJob(_ string, matrix protocol.MatrixConfig, block int, position string) protocol.MatrixJob {
	name := fmt.Sprintf("block-%03d-%s.json", block, position)
	return protocol.MatrixJob{
		ID: "raw-control-" + strings.TrimSuffix(name, ".json"), CaseID: matrix.RawControl.RunID,
		Subject: protocol.SubjectRaw, Block: block, Control: position, Result: filepath.ToSlash(filepath.Join("controls", "raw", name)),
	}
}

func matrixOrder(seed int64, block int, caseID string) uint64 {
	hash := fnv.New64a()
	_, _ = fmt.Fprintf(hash, "%d/%d/%s", seed, block, caseID)
	return hash.Sum64()
}

func matrixJobConfig(matrix protocol.MatrixConfig, job protocol.MatrixJob) (protocol.Config, int, error) {
	if job.Control != "" {
		if matrix.RawControl == nil {
			return protocol.Config{}, 0, errors.New("raw control job has no configuration")
		}
		config := *matrix.RawControl
		return config, job.Block*2 + map[string]int{"before": 0, "after": 1}[job.Control], nil
	}
	index := slices.IndexFunc(matrix.Cases, func(config protocol.Config) bool { return config.RunID == job.CaseID })
	if index < 0 {
		return protocol.Config{}, 0, fmt.Errorf("matrix case %s is missing", job.CaseID)
	}
	return matrix.Cases[index], job.Block, nil
}

func summarizeMatrix(matrix protocol.MatrixConfig) error {
	root := filepath.Join(matrix.OutputDirectory, matrix.MatrixID)
	var state protocol.MatrixState
	stateFile, err := os.Open(filepath.Join(root, "state.json"))
	if err != nil {
		return err
	}
	decodeErr := json.NewDecoder(stateFile).Decode(&state)
	closeErr := stateFile.Close()
	if decodeErr != nil || closeErr != nil {
		return errors.Join(decodeErr, closeErr)
	}
	summary, buildErr := report.Build(root, matrix, state)
	if err = protocol.WriteJSON(filepath.Join(root, "summary.json"), summary); err != nil {
		return errors.Join(buildErr, err)
	}
	if err = os.WriteFile(filepath.Join(root, "summary.md"), report.Markdown(summary), 0o644); err != nil {
		return errors.Join(buildErr, err)
	}
	return buildErr
}

func failedRepetition(config protocol.Config, index int, warmup bool, report runner.Report) protocol.Repetition {
	startedAt := report.Trace.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	finishedAt := report.Trace.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now()
	}
	proof := report.PathProof
	if proof.ObservedAt.IsZero() {
		proof = protocol.PathProof{Valid: false, Method: "path proof phase was not reached", ObservedAt: finishedAt}
	}
	return protocol.Repetition{
		ProtocolVersion: protocol.Version, RunID: config.RunID, Subject: config.Subject.Kind, Index: index, Warmup: warmup,
		StartedAt: startedAt, DurationNS: finishedAt.Sub(startedAt).Nanoseconds(), PathProof: proof,
		Validity: protocol.Validity{Valid: false}, Resources: protocol.ResourceDelta{WallNanoseconds: finishedAt.Sub(startedAt).Nanoseconds()},
	}
}

func writeArtifacts(resultDirectory string, kind protocol.SubjectKind, repetition string, artifacts []subject.Artifact) ([]protocol.ArtifactRecord, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	directory := filepath.Join(resultDirectory, string(kind), "artifacts", repetition)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	records := make([]protocol.ArtifactRecord, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Name == "" || filepath.Base(artifact.Name) != artifact.Name || artifact.Name == "." {
			return records, fmt.Errorf("invalid artifact name %q", artifact.Name)
		}
		path := filepath.Join(directory, artifact.Name)
		if err := os.WriteFile(path, artifact.Content, 0o600); err != nil {
			return records, err
		}
		sum := sha256.Sum256(artifact.Content)
		records = append(records, protocol.ArtifactRecord{Name: filepath.ToSlash(filepath.Join("artifacts", repetition, artifact.Name)), SHA256: fmt.Sprintf("%x", sum), Size: int64(len(artifact.Content)), Truncated: artifact.Truncated})
	}
	return records, nil
}

func makeSubject(config protocol.Config) subject.Subject {
	if config.Subject.Kind == protocol.SubjectRaw {
		return raw.New(config.Execution.WorkerUID)
	}
	return benchSingBox.New(config, nil)
}

type processProvider interface{ ProcessID() int }

func measure(ctx context.Context, config protocol.Config, selected subject.Subject, index int, warmup bool, proof protocol.PathProof) (protocol.Repetition, error) {
	var hostBefore metrics.HostSnapshot
	var hostAfter metrics.HostSnapshot
	var subjectBefore metrics.ProcessSnapshot
	var subjectAfter metrics.ProcessSnapshot
	var subjectDeltaErr error
	provider, hasProcess := selected.(processProvider)
	runtimeProvider, hasRuntimeDiagnostics := selected.(subject.RuntimeDiagnosticsProvider)
	hasRuntimeDiagnostics = hasRuntimeDiagnostics && (selected.Kind() == protocol.SubjectEBPFTC || selected.Kind() == protocol.SubjectEBPFCgroup)
	var runtimeBefore json.RawMessage
	var runtimeAfter json.RawMessage
	request := makeWorkerRequest(config, index, false)
	workerResult, workloadErr := worker.RunProcess(ctx, "", worker.TemporaryRoot(config.Execution.TemporaryDirectory), request, worker.ProcessHooks{
		BeforeStart: func(ready worker.Ready) error {
			var runtimeErr error
			if hasRuntimeDiagnostics {
				runtimeBefore, runtimeErr = runtimeProvider.ObserveRuntimeDiagnostics(ctx)
			}
			var err error
			hostBefore, err = metrics.ReadHost(measuredInterfaces(config))
			if err != nil {
				return errors.Join(runtimeErr, err)
			}
			if hasProcess && provider.ProcessID() > 0 {
				subjectBefore, err = metrics.ReadProcess(provider.ProcessID())
			}
			return errors.Join(runtimeErr, err)
		},
		AfterWorkload: func() error {
			var errs []error
			var err error
			hostAfter, err = metrics.ReadHost(measuredInterfaces(config))
			if err != nil {
				errs = append(errs, err)
			}
			if hasProcess && provider.ProcessID() > 0 {
				subjectAfter, err = metrics.ReadProcess(provider.ProcessID())
				if err != nil {
					errs = append(errs, err)
				}
			}
			if hasRuntimeDiagnostics {
				runtimeAfter, err = runtimeProvider.ObserveRuntimeDiagnostics(ctx)
				if err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	})
	if workerResult.Workload.Timing.StartedAt.IsZero() {
		return protocol.Repetition{}, workloadErr
	}
	hostDelta, systemDeltaErr := metrics.HostDelta(hostBefore, hostAfter)
	var subjectDelta metrics.ProcessSnapshot
	if hasProcess && provider.ProcessID() > 0 {
		subjectDelta, subjectDeltaErr = metrics.ProcessDelta(subjectBefore, subjectAfter)
	}
	var runtimeErr error
	if hasRuntimeDiagnostics && len(runtimeBefore) > 0 && len(runtimeAfter) > 0 {
		runtimeErr = runtimeProvider.ValidateRuntimeDiagnostics(runtimeBefore, runtimeAfter)
	}
	err := errors.Join(workloadErr, systemDeltaErr, subjectDeltaErr, runtimeErr)
	validity := protocol.Validity{Valid: err == nil && workerResult.Workload.Counters.Failed == 0 && workerResult.Workload.Counters.Corrupt == 0}
	if err != nil {
		validity.Reasons = []string{err.Error()}
	}
	startedAt := workerResult.Workload.Timing.StartedAt
	finishedAt := workerResult.Workload.Timing.FinishedAt
	duration := finishedAt.Sub(startedAt)
	result := protocol.Repetition{
		ProtocolVersion: protocol.Version, RunID: config.RunID, Subject: config.Subject.Kind, Index: index, Warmup: warmup,
		StartedAt: startedAt, DurationNS: duration.Nanoseconds(), Counters: workerResult.Workload.Counters, LatencyNS: workerResult.Workload.LatencyNS,
		Worker: &workerResult.Identity, WorkloadTiming: &workerResult.Workload.Timing, PathProof: proof, Validity: validity,
		Resources: protocol.ResourceDelta{
			WallNanoseconds: duration.Nanoseconds(), ClientUserTicks: workerResult.Process.UserTicks, ClientSystemTicks: workerResult.Process.SystemTicks,
			ClientReadBytes: workerResult.Process.ReadBytes, ClientWriteBytes: workerResult.Process.WriteBytes, ClientRSSBytes: workerResult.Process.RSSBytes,
			ClientRunNanoseconds: workerResult.Process.RunNanoseconds, ClientPSSBytes: workerResult.Process.PSSBytes,
			ClientUSSBytes: workerResult.Process.USSBytes, ClientHighWaterRSSBytes: workerResult.Process.HighWaterRSSBytes,
			ClientSwapBytes: workerResult.Process.SwapBytes, ClientMinorFaults: workerResult.Process.MinorFaults,
			ClientMajorFaults: workerResult.Process.MajorFaults, ClientVoluntarySwitches: workerResult.Process.VoluntarySwitches,
			ClientInvoluntarySwitches: workerResult.Process.InvoluntarySwitches, ClientThreads: workerResult.Process.Threads,
			ClientFileDescriptors: workerResult.Process.FileDescriptors, ClientSocketDescriptors: workerResult.Process.SocketFileDescriptors,
			SubjectUserTicks: subjectDelta.UserTicks, SubjectSystemTicks: subjectDelta.SystemTicks, SubjectReadBytes: subjectDelta.ReadBytes,
			SubjectRunNanoseconds: subjectDelta.RunNanoseconds,
			SubjectWriteBytes:     subjectDelta.WriteBytes, SubjectRSSBytes: subjectDelta.RSSBytes, SubjectPSSBytes: subjectDelta.PSSBytes,
			SubjectUSSBytes: subjectDelta.USSBytes, SubjectHighWaterRSSBytes: subjectDelta.HighWaterRSSBytes, SubjectSwapBytes: subjectDelta.SwapBytes,
			SubjectMinorFaults: subjectDelta.MinorFaults, SubjectMajorFaults: subjectDelta.MajorFaults,
			SubjectVoluntarySwitches: subjectDelta.VoluntarySwitches, SubjectInvoluntarySwitches: subjectDelta.InvoluntarySwitches,
			SubjectThreads: subjectDelta.Threads, SubjectFileDescriptors: subjectDelta.FileDescriptors, SubjectSocketDescriptors: subjectDelta.SocketFileDescriptors,
			SubjectBPFProgramDescriptors: subjectDelta.BPFProgramDescriptors, SubjectBPFLinkDescriptors: subjectDelta.BPFLinkDescriptors,
			SubjectBPFMapMemlockBytes: subjectDelta.BPFMapMemlockBytes, SubjectBPFMaps: convertBPFMaps(subjectDelta.BPFMaps),
			SystemCPUTicks: hostDelta.System.CPUTicks, SystemCPUByCore: hostDelta.System.CPUByCore,
			SystemSoftIRQs: hostDelta.System.SoftIRQs, SystemContextSwitches: hostDelta.System.ContextSwitches,
			SystemProcessesCreated: hostDelta.System.Processes, SystemPageFaults: hostDelta.System.PageFaults,
			SystemMajorPageFaults: hostDelta.System.MajorPageFaults, SystemMigrations: hostDelta.System.Migrations,
			Interfaces: convertInterfaces(hostDelta.Interfaces), ThermalBefore: hostBefore.Thermal, ThermalAfter: hostAfter.Thermal,
			CPUFrequencyBefore: hostBefore.CPUFrequency, CPUFrequencyAfter: hostAfter.CPUFrequency,
			CPUIdleTime: hostDelta.CPUIdleTime, CPUIdleUsage: hostDelta.CPUIdleUsage,
			WakeupSources:        convertWakeupSources(hostDelta.WakeupSources),
			ConntrackCountBefore: hostBefore.ConntrackCount, ConntrackCountAfter: hostAfter.ConntrackCount,
		},
	}
	if hasRuntimeDiagnostics {
		result.Runtime = &protocol.RuntimeDiagnostics{Before: runtimeBefore, After: runtimeAfter}
	}
	return result, err
}

func convertWakeupSources(source map[string]metrics.WakeupSource) map[string]protocol.WakeupSourceCounters {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]protocol.WakeupSourceCounters, len(source))
	for name, counters := range source {
		result[name] = protocol.WakeupSourceCounters{
			EventCount: counters.EventCount, WakeupCount: counters.WakeupCount,
			TotalTime: counters.TotalTime, PreventSuspendTime: counters.PreventSuspendTime,
		}
	}
	return result
}

func measuredInterfaces(config protocol.Config) []string {
	interfaces := make([]string, 0, 2)
	if config.Subject.OutboundInterface != "" {
		interfaces = append(interfaces, config.Subject.OutboundInterface)
	}
	if config.Subject.Kind == protocol.SubjectTun || config.Subject.Kind == protocol.SubjectTunAuto {
		interfaces = append(interfaces, config.Subject.TunName)
	}
	return interfaces
}

func convertBPFMaps(source []metrics.BPFMapSnapshot) []protocol.BPFMapCounters {
	if len(source) == 0 {
		return nil
	}
	result := make([]protocol.BPFMapCounters, len(source))
	for index, item := range source {
		result[index] = protocol.BPFMapCounters{
			ID: item.ID, Type: item.Type, KeySize: item.KeySize, ValueSize: item.ValueSize,
			MaxEntries: item.MaxEntries, Flags: item.Flags, Memlock: item.Memlock,
		}
	}
	return result
}

func convertInterfaces(source map[string]netdev.Stats) map[string]protocol.InterfaceCounters {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]protocol.InterfaceCounters, len(source))
	for name, stats := range source {
		result[name] = protocol.InterfaceCounters{
			RXBytes: stats.RXBytes, RXPackets: stats.RXPackets, RXErrors: stats.RXErrors, RXDropped: stats.RXDropped,
			TXBytes: stats.TXBytes, TXPackets: stats.TXPackets, TXErrors: stats.TXErrors, TXDropped: stats.TXDropped,
		}
	}
	return result
}

func runWarmup(ctx context.Context, config protocol.Config, index int) (subject.WarmupEvidence, error) {
	warmup := config.Workload
	warmup.Requests = max(8, warmup.Connections, warmup.Flows)
	warmup.DurationMS = 0
	warmup.Mode = protocol.ModeEcho
	warmup.PayloadBytes = min(warmup.PayloadBytes, 64)
	warmup.OfferedPPS = 0
	warmupConfig := config
	warmupConfig.Workload = warmup
	result, err := worker.RunProcess(ctx, "", worker.TemporaryRoot(config.Execution.TemporaryDirectory), makeWorkerRequest(warmupConfig, index, true), worker.ProcessHooks{})
	details, _ := json.Marshal(result)
	counters := result.Workload.Counters
	valid := err == nil && counters.Operations > 0 && counters.Failed == 0 && counters.Corrupt == 0 && len(result.Workload.SocketPaths) > 0
	return subject.WarmupEvidence{Valid: valid, Token: fmt.Sprintf("%s-proof-%d", config.RunID, index), Details: details}, err
}

func makeWorkerRequest(config protocol.Config, index int, collectProof bool) worker.Request {
	cgroupPath := ""
	if config.Subject.Kind == protocol.SubjectEBPFCgroup {
		cgroupPath = config.Subject.CgroupPath
	}
	return worker.Request{
		ProtocolVersion: protocol.Version, RunID: config.RunID, Index: index, Workload: config.Workload,
		WorkerUID: config.Execution.WorkerUID, CgroupPath: cgroupPath, CollectProof: collectProof,
	}
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return version
}

func signalContext() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), benchmarkSignals()...)
	return ctx
}
