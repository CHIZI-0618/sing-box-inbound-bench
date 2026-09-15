package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/metrics"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/runner"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject/raw"
	benchSingBox "github.com/CHIZI-0618/sing-box-inbound-bench/internal/subject/singbox"
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
		return errors.New("usage: inbound-bench <run|tcp-server|udp-server> [options]")
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
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
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
	hostname, _ := os.Hostname()
	manifest := protocol.Manifest{
		ProtocolVersion: protocol.Version, RunID: config.RunID, CreatedAt: time.Now(), ToolVersion: buildVersion(),
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Hostname: hostname, Subject: config.Subject.Kind,
	}
	if err = protocol.WriteJSON(filepath.Join(resultDirectory, "manifest.json"), manifest); err != nil {
		return err
	}
	redacted := config
	if redacted.Subject.APIToken != "" {
		redacted.Subject.APIToken = "<redacted>"
	}
	if err = protocol.WriteJSON(filepath.Join(resultDirectory, "config.json"), redacted); err != nil {
		return err
	}
	runContext, stopSignals := signal.NotifyContext(context.Background(), benchmarkSignals()...)
	defer stopSignals()
	total := config.Execution.WarmupRepetitions + config.Execution.Repetitions
	for index := 0; index < total; index++ {
		warmupRepetition := index < config.Execution.WarmupRepetitions
		selected := makeSubject(config)
		var repetition protocol.Repetition
		report, executeErr := runner.Execute(runContext, selected,
			func(ctx context.Context) (subject.WarmupEvidence, error) { return runWarmup(ctx, config, index) },
			func(ctx context.Context, proof protocol.PathProof) error {
				result, measureErr := measure(ctx, config, selected, index, warmupRepetition, proof)
				repetition = result
				return measureErr
			})
		name := fmt.Sprintf("rep-%03d.json", index-config.Execution.WarmupRepetitions)
		if warmupRepetition {
			name = fmt.Sprintf("warmup-%03d.json", index)
		}
		if repetition.ProtocolVersion == "" {
			repetition = failedRepetition(config, index, warmupRepetition, report)
		}
		repetition.Execution = report.Trace
		if repetition.PathProof.ObservedAt.IsZero() {
			repetition.PathProof = report.PathProof
		}
		artifactRecords, artifactErr := writeArtifacts(resultDirectory, config.Subject.Kind, strings.TrimSuffix(name, ".json"), report.Artifacts)
		repetition.Artifacts = artifactRecords
		executeErr = errors.Join(executeErr, artifactErr)
		if executeErr != nil {
			repetition.Validity.Valid = false
			repetition.Validity.Reasons = append(repetition.Validity.Reasons, executeErr.Error())
		}
		if writeErr := protocol.WriteJSON(filepath.Join(resultDirectory, string(config.Subject.Kind), name), repetition); writeErr != nil {
			return writeErr
		}
		if executeErr != nil {
			return fmt.Errorf("repetition %d: %w", index, executeErr)
		}
	}
	return nil
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
		return raw.New()
	}
	return benchSingBox.New(config, nil)
}

type processProvider interface{ ProcessID() int }

func measure(ctx context.Context, config protocol.Config, selected subject.Subject, index int, warmup bool, proof protocol.PathProof) (protocol.Repetition, error) {
	startedAt := time.Now()
	clientBefore, err := metrics.ReadProcess(os.Getpid())
	if err != nil {
		return protocol.Repetition{}, err
	}
	systemBefore, err := metrics.ReadSystem()
	if err != nil {
		return protocol.Repetition{}, err
	}
	var subjectBefore metrics.ProcessSnapshot
	provider, hasProcess := selected.(processProvider)
	if hasProcess && provider.ProcessID() > 0 {
		subjectBefore, err = metrics.ReadProcess(provider.ProcessID())
		if err != nil {
			return protocol.Repetition{}, err
		}
	}
	counters, latency, workloadErr := runWorkload(ctx, config.Workload, config.RunID, index)
	duration := time.Since(startedAt)
	clientAfter, clientErr := metrics.ReadProcess(os.Getpid())
	systemAfter, systemErr := metrics.ReadSystem()
	clientDelta, deltaErr := metrics.ProcessDelta(clientBefore, clientAfter)
	systemDelta, systemDeltaErr := metrics.SystemDelta(systemBefore, systemAfter)
	var subjectDelta metrics.ProcessSnapshot
	if hasProcess && provider.ProcessID() > 0 {
		after, readErr := metrics.ReadProcess(provider.ProcessID())
		if readErr == nil {
			subjectDelta, readErr = metrics.ProcessDelta(subjectBefore, after)
		}
		if err == nil {
			err = readErr
		}
	}
	err = errors.Join(err, workloadErr, clientErr, systemErr, deltaErr, systemDeltaErr)
	validity := protocol.Validity{Valid: err == nil && counters.Failed == 0 && counters.Corrupt == 0}
	if err != nil {
		validity.Reasons = []string{err.Error()}
	}
	result := protocol.Repetition{
		ProtocolVersion: protocol.Version, RunID: config.RunID, Subject: config.Subject.Kind, Index: index, Warmup: warmup,
		StartedAt: startedAt, DurationNS: duration.Nanoseconds(), Counters: counters, LatencyNS: latency, PathProof: proof, Validity: validity,
		Resources: protocol.ResourceDelta{
			WallNanoseconds: duration.Nanoseconds(), ClientUserTicks: clientDelta.UserTicks, ClientSystemTicks: clientDelta.SystemTicks,
			ClientReadBytes: clientDelta.ReadBytes, ClientWriteBytes: clientDelta.WriteBytes, ClientRSSBytes: clientDelta.RSSBytes,
			ClientRunNanoseconds: clientDelta.RunNanoseconds,
			SubjectUserTicks:     subjectDelta.UserTicks, SubjectSystemTicks: subjectDelta.SystemTicks, SubjectReadBytes: subjectDelta.ReadBytes,
			SubjectRunNanoseconds: subjectDelta.RunNanoseconds,
			SubjectWriteBytes:     subjectDelta.WriteBytes, SubjectRSSBytes: subjectDelta.RSSBytes, SystemCPUTicks: systemDelta.CPUTicks,
			SystemSoftIRQs: systemDelta.SoftIRQs, SystemContextSwitches: systemDelta.ContextSwitches, SystemProcessesCreated: systemDelta.Processes,
		},
	}
	return result, err
}

func runWarmup(ctx context.Context, config protocol.Config, index int) (subject.WarmupEvidence, error) {
	warmup := config.Workload
	warmup.Requests = max(8, warmup.Connections, warmup.Flows)
	warmup.DurationMS = 0
	warmup.OfferedPPS = 0
	counters, _, err := runWorkload(ctx, warmup, config.RunID+"-proof", index)
	details, _ := json.Marshal(counters)
	return subject.WarmupEvidence{Valid: err == nil && counters.Operations > 0 && counters.Failed == 0 && counters.Corrupt == 0, Token: fmt.Sprintf("%s-proof-%d", config.RunID, index), Details: details}, err
}

func runWorkload(ctx context.Context, workload protocol.WorkloadConfig, runID string, index int) (protocol.Counters, []int64, error) {
	timeout := time.Duration(workload.TimeoutMS) * time.Millisecond
	duration := time.Duration(workload.DurationMS) * time.Millisecond
	if workload.Protocol == protocol.ProtocolTCP {
		return benchTCP.Run(ctx, benchTCP.ClientConfig{Target: workload.Target, Mode: workload.Mode, PayloadBytes: workload.PayloadBytes, Requests: workload.Requests, Duration: duration, Connections: workload.Connections, Timeout: timeout})
	}
	hash := fnv.New32a()
	_, _ = fmt.Fprintf(hash, "%s-%d", runID, index)
	return benchUDP.Run(ctx, benchUDP.ClientConfig{Target: workload.Target, Mode: workload.Mode, PayloadBytes: workload.PayloadBytes, Requests: workload.Requests, Duration: duration, Flows: workload.Flows, OfferedPPS: workload.OfferedPPS, Timeout: timeout, RunHash: hash.Sum32()})
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
