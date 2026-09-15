package report

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type CaseSummary struct {
	CaseID                 string               `json:"case_id"`
	Subject                protocol.SubjectKind `json:"subject"`
	ValidRepetitions       int                  `json:"valid_repetitions"`
	InvalidRepetitions     int                  `json:"invalid_repetitions"`
	OperationsPerSecond    float64              `json:"operations_per_second_median"`
	DeliveredBitsPerSecond float64              `json:"delivered_bits_per_second_median"`
	LatencyP50NS           int64                `json:"latency_p50_ns,omitempty"`
	LatencyP99NS           int64                `json:"latency_p99_ns,omitempty"`
	ClientCPUCores         float64              `json:"client_cpu_cores_median"`
	SubjectCPUCores        float64              `json:"subject_cpu_cores_median"`
	SubjectCPUSecondsGiB   float64              `json:"subject_cpu_seconds_per_gib_median,omitempty"`
}

type ControlDrift struct {
	Block   int     `json:"block"`
	Before  float64 `json:"before_bits_per_second"`
	After   float64 `json:"after_bits_per_second"`
	Percent float64 `json:"percent"`
	Valid   bool    `json:"valid"`
}

type Summary struct {
	ProtocolVersion string         `json:"protocol_version"`
	MatrixID        string         `json:"matrix_id"`
	Cases           []CaseSummary  `json:"cases"`
	RawControlDrift []ControlDrift `json:"raw_control_drift,omitempty"`
	Warnings        []string       `json:"warnings,omitempty"`
}

func Build(root string, matrix protocol.MatrixConfig, state protocol.MatrixState) (Summary, error) {
	result := Summary{ProtocolVersion: protocol.Version, MatrixID: matrix.MatrixID}
	caseConfigs := make(map[string]protocol.Config)
	for _, config := range matrix.Cases {
		caseConfigs[config.RunID] = config
	}
	type values struct {
		ops, bits, clientCPU, subjectCPU, cpuGiB []float64
		latency                                  []int64
		valid, invalid                           int
	}
	byCase := make(map[string]*values)
	control := make(map[int]map[string]float64)
	var errs []error
	for _, job := range state.Jobs {
		if !job.Complete {
			continue
		}
		path, pathErr := ownedResultPath(root, job.Result)
		if pathErr != nil {
			errs = append(errs, pathErr)
			continue
		}
		repetition, decodeErr := protocol.DecodeRepetition(path)
		if decodeErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", job.ID, decodeErr))
			continue
		}
		if job.Control != "" {
			if repetition.Validity.Valid {
				if control[job.Block] == nil {
					control[job.Block] = make(map[string]float64)
				}
				control[job.Block][job.Control] = deliveredBitsPerSecond(repetition, *matrix.RawControl)
			}
			continue
		}
		if repetition.Warmup {
			continue
		}
		config, exists := caseConfigs[job.CaseID]
		if !exists {
			errs = append(errs, fmt.Errorf("missing config for case %s", job.CaseID))
			continue
		}
		value := byCase[job.CaseID]
		if value == nil {
			value = &values{}
			byCase[job.CaseID] = value
		}
		if !repetition.Validity.Valid {
			value.invalid++
			continue
		}
		value.valid++
		seconds := float64(repetition.DurationNS) / 1e9
		if seconds > 0 {
			value.ops = append(value.ops, float64(repetition.Counters.Operations)/seconds)
			bits := deliveredBitsPerSecond(repetition, config)
			value.bits = append(value.bits, bits)
			value.clientCPU = append(value.clientCPU, float64(repetition.Resources.ClientRunNanoseconds)/float64(repetition.DurationNS))
			value.subjectCPU = append(value.subjectCPU, float64(repetition.Resources.SubjectRunNanoseconds)/float64(repetition.DurationNS))
			delivered := deliveredBytes(repetition, config)
			if delivered > 0 {
				value.cpuGiB = append(value.cpuGiB, float64(repetition.Resources.SubjectRunNanoseconds)/1e9/(float64(delivered)/(1<<30)))
			}
		}
		value.latency = append(value.latency, repetition.LatencyNS...)
	}
	for _, config := range matrix.Cases {
		value := byCase[config.RunID]
		item := CaseSummary{CaseID: config.RunID, Subject: config.Subject.Kind}
		if value != nil {
			item.ValidRepetitions, item.InvalidRepetitions = value.valid, value.invalid
			item.OperationsPerSecond = median(value.ops)
			item.DeliveredBitsPerSecond = median(value.bits)
			item.ClientCPUCores = median(value.clientCPU)
			item.SubjectCPUCores = median(value.subjectCPU)
			item.SubjectCPUSecondsGiB = median(value.cpuGiB)
			item.LatencyP50NS = percentile(value.latency, 0.50)
			item.LatencyP99NS = percentile(value.latency, 0.99)
		}
		result.Cases = append(result.Cases, item)
	}
	if matrix.RawControl != nil {
		for block := 0; block < maxBlocks(matrix.Cases); block++ {
			pair := control[block]
			if pair == nil || pair["before"] <= 0 || pair["after"] <= 0 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("block %d is missing a valid raw control pair", block))
				continue
			}
			percent := math.Abs(pair["after"]-pair["before"]) / pair["before"] * 100
			drift := ControlDrift{Block: block, Before: pair["before"], After: pair["after"], Percent: percent, Valid: percent <= 5}
			result.RawControlDrift = append(result.RawControlDrift, drift)
			if !drift.Valid {
				result.Warnings = append(result.Warnings, fmt.Sprintf("block %d raw throughput drift %.2f%% exceeds 5%%", block, percent))
			}
		}
	}
	return result, errors.Join(errs...)
}

func Markdown(summary Summary) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "# Matrix summary: %s\n\n", summary.MatrixID)
	output.WriteString("Only non-warmup repetitions with `validity.valid=true` are included. Rates are medians.\n\n")
	output.WriteString("| Case | Subject | Valid | Invalid | Ops/s | Delivered Mbit/s | p50 ms | p99 ms | Client CPU cores | Subject CPU cores | Subject CPU s/GiB |\n")
	output.WriteString("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	for _, item := range summary.Cases {
		fmt.Fprintf(&output, "| %s | %s | %d | %d | %.2f | %.2f | %.3f | %.3f | %.3f | %.3f | %.3f |\n",
			item.CaseID, item.Subject, item.ValidRepetitions, item.InvalidRepetitions, item.OperationsPerSecond,
			item.DeliveredBitsPerSecond/1e6, float64(item.LatencyP50NS)/1e6, float64(item.LatencyP99NS)/1e6,
			item.ClientCPUCores, item.SubjectCPUCores, item.SubjectCPUSecondsGiB)
	}
	if len(summary.Warnings) > 0 {
		output.WriteString("\n## Validity warnings\n\n")
		for _, warning := range summary.Warnings {
			fmt.Fprintf(&output, "- %s\n", warning)
		}
	}
	return []byte(output.String())
}

func deliveredBytes(repetition protocol.Repetition, config protocol.Config) uint64 {
	switch config.Workload.Mode {
	case protocol.ModeBulkUpload:
		return repetition.Counters.BytesSent
	case protocol.ModeBulkDownload:
		return repetition.Counters.BytesReceived
	default:
		return min(repetition.Counters.BytesSent, repetition.Counters.BytesReceived)
	}
}

func deliveredBitsPerSecond(repetition protocol.Repetition, config protocol.Config) float64 {
	if repetition.DurationNS <= 0 {
		return 0
	}
	return float64(deliveredBytes(repetition, config)) * 8 * 1e9 / float64(repetition.DurationNS)
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	values = slices.Clone(values)
	slices.Sort(values)
	middle := len(values) / 2
	if len(values)%2 == 0 {
		return (values[middle-1] + values[middle]) / 2
	}
	return values[middle]
}

func percentile(values []int64, percentile float64) int64 {
	if len(values) == 0 {
		return 0
	}
	values = slices.Clone(values)
	slices.Sort(values)
	index := int(math.Ceil(percentile*float64(len(values)))) - 1
	return values[max(0, min(index, len(values)-1))]
}

func maxBlocks(configs []protocol.Config) int {
	result := 0
	for _, config := range configs {
		result = max(result, config.Execution.WarmupRepetitions+config.Execution.Repetitions)
	}
	return result
}

func ownedResultPath(root, relative string) (string, error) {
	if filepath.IsAbs(relative) {
		return "", errors.New("result path must be relative")
	}
	root = filepath.Clean(root)
	path := filepath.Join(root, filepath.FromSlash(relative))
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("result path escapes matrix root")
	}
	return path, nil
}
