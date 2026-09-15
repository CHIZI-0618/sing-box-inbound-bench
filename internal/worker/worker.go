package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/cgroup"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/metrics"
	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
	benchTCP "github.com/CHIZI-0618/sing-box-inbound-bench/internal/workload/tcp"
	benchUDP "github.com/CHIZI-0618/sing-box-inbound-bench/internal/workload/udp"
)

type Request struct {
	ProtocolVersion string                  `json:"protocol_version"`
	RunID           string                  `json:"run_id"`
	Index           int                     `json:"index"`
	Workload        protocol.WorkloadConfig `json:"workload"`
	WorkerUID       *uint32                 `json:"worker_uid,omitempty"`
	CgroupPath      string                  `json:"cgroup_path,omitempty"`
	CollectProof    bool                    `json:"collect_proof"`
}

type Ready struct {
	ProtocolVersion string                  `json:"protocol_version"`
	Type            string                  `json:"type"`
	Identity        protocol.WorkerIdentity `json:"identity"`
}

type Finished struct {
	ProtocolVersion string `json:"protocol_version"`
	Type            string `json:"type"`
	PID             int    `json:"pid"`
}

type Result struct {
	ProtocolVersion string                  `json:"protocol_version"`
	Type            string                  `json:"type"`
	Identity        protocol.WorkerIdentity `json:"identity"`
	Workload        protocol.WorkloadResult `json:"workload"`
	Process         metrics.ProcessSnapshot `json:"process"`
	Error           string                  `json:"error,omitempty"`
}

func ReadRequest(path string) (Request, error) {
	file, err := os.Open(path)
	if err != nil {
		return Request{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var request Request
	if err = decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	if request.ProtocolVersion != protocol.Version {
		return Request{}, fmt.Errorf("worker protocol_version must be %q", protocol.Version)
	}
	validation := protocol.Config{
		ProtocolVersion: protocol.Version, RunID: request.RunID, Subject: protocol.SubjectConfig{Kind: protocol.SubjectRaw}, Workload: request.Workload,
		Execution: protocol.ExecutionConfig{Repetitions: 1, OutputDirectory: "."},
	}
	if err = validation.Validate(); err != nil {
		return Request{}, fmt.Errorf("worker workload: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Request{}, errors.New("worker request contains multiple JSON values")
		}
		return Request{}, err
	}
	return request, nil
}

// Serve prepares process identity before acknowledging readiness. No workload
// socket can be created until the controller sends the explicit start token.
func Serve(ctx context.Context, request Request, input io.Reader, output io.Writer) error {
	identity := protocol.WorkerIdentity{PID: os.Getpid(), CgroupPath: request.CgroupPath}
	if request.CgroupPath != "" {
		if err := cgroup.Join(request.CgroupPath, identity.PID); err != nil {
			return err
		}
		identity.CgroupVerified = true
	}
	uid, err := prepareUID(request.WorkerUID)
	if err != nil {
		return err
	}
	identity.UID = uid
	encoder := json.NewEncoder(output)
	if err = encoder.Encode(Ready{ProtocolVersion: protocol.Version, Type: "ready", Identity: identity}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(input)
	if !scanner.Scan() {
		if err = scanner.Err(); err != nil {
			return err
		}
		return errors.New("worker start token was not received")
	}
	if scanner.Text() != "start" {
		return errors.New("invalid worker start token")
	}
	before, beforeErr := metrics.ReadProcess(os.Getpid())
	var workloadResult protocol.WorkloadResult
	var workloadErr error
	var idleConnections []net.Conn
	if request.Workload.Protocol == protocol.ProtocolTCP && request.Workload.Mode == protocol.ModeIdle {
		workloadResult, idleConnections, workloadErr = benchTCP.RunIdle(ctx, benchTCP.ClientConfig{
			Target: request.Workload.Target, Mode: request.Workload.Mode, PayloadBytes: request.Workload.PayloadBytes,
			Duration: time.Duration(request.Workload.DurationMS) * time.Millisecond, Connections: request.Workload.Connections,
			Timeout: time.Duration(request.Workload.TimeoutMS) * time.Millisecond,
		})
		defer closeWorkerConnections(idleConnections)
	} else {
		workloadResult, workloadErr = runWorkload(ctx, request)
	}
	after, afterErr := metrics.ReadProcess(os.Getpid())
	delta, deltaErr := metrics.ProcessDelta(before, after)
	resultErr := errors.Join(beforeErr, workloadErr, afterErr, deltaErr)
	result := Result{ProtocolVersion: protocol.Version, Type: "result", Identity: identity, Workload: workloadResult, Process: delta}
	if resultErr != nil {
		result.Error = resultErr.Error()
	}
	if err = encoder.Encode(Finished{ProtocolVersion: protocol.Version, Type: "finished", PID: identity.PID}); err != nil {
		return err
	}
	if !scanner.Scan() {
		if err = scanner.Err(); err != nil {
			return err
		}
		return errors.New("worker collect token was not received")
	}
	if scanner.Text() != "collect" {
		return errors.New("invalid worker collect token")
	}
	closeWorkerConnections(idleConnections)
	idleConnections = nil
	if err = encoder.Encode(result); err != nil {
		return err
	}
	return nil
}

func closeWorkerConnections(connections []net.Conn) {
	for _, connection := range connections {
		if connection != nil {
			_ = connection.Close()
		}
	}
}

func runWorkload(ctx context.Context, request Request) (protocol.WorkloadResult, error) {
	workload := request.Workload
	timeout := time.Duration(workload.TimeoutMS) * time.Millisecond
	duration := time.Duration(workload.DurationMS) * time.Millisecond
	if workload.Protocol == protocol.ProtocolTCP {
		return benchTCP.RunDetailed(ctx, benchTCP.ClientConfig{
			Target: workload.Target, Mode: workload.Mode, PayloadBytes: workload.PayloadBytes, Requests: workload.Requests,
			Duration: duration, Connections: workload.Connections, Timeout: timeout, CollectProof: request.CollectProof,
		})
	}
	hash := fnv.New32a()
	_, _ = fmt.Fprintf(hash, "%s-%d", request.RunID, request.Index)
	return benchUDP.RunDetailed(ctx, benchUDP.ClientConfig{
		Target: workload.Target, Mode: workload.Mode, PayloadBytes: workload.PayloadBytes, Requests: workload.Requests,
		Duration: duration, Flows: workload.Flows, OfferedPPS: workload.OfferedPPS, Timeout: timeout,
		RunHash: hash.Sum32(), CollectProof: request.CollectProof,
	})
}
