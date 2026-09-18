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
	CaseID                  string                  `json:"case_id"`
	Subject                 protocol.SubjectKind    `json:"subject"`
	ValidRepetitions        int                     `json:"valid_repetitions"`
	InvalidRepetitions      int                     `json:"invalid_repetitions"`
	OperationsPerSecond     float64                 `json:"operations_per_second_median"`
	SuccessPercent          float64                 `json:"success_percent_median,omitempty"`
	DeliveredBitsPerSecond  float64                 `json:"delivered_bits_per_second_median"`
	LatencyP50NS            int64                   `json:"latency_p50_ns,omitempty"`
	LatencyP95NS            int64                   `json:"latency_p95_ns,omitempty"`
	LatencyP99NS            int64                   `json:"latency_p99_ns,omitempty"`
	LatencyP999NS           int64                   `json:"latency_p999_ns,omitempty"`
	ConnectLatencyP50NS     int64                   `json:"connect_latency_p50_ns,omitempty"`
	ConnectLatencyP95NS     int64                   `json:"connect_latency_p95_ns,omitempty"`
	ConnectLatencyP99NS     int64                   `json:"connect_latency_p99_ns,omitempty"`
	ApplicationLatencyP50NS int64                   `json:"application_latency_p50_ns,omitempty"`
	ApplicationLatencyP95NS int64                   `json:"application_latency_p95_ns,omitempty"`
	ApplicationLatencyP99NS int64                   `json:"application_latency_p99_ns,omitempty"`
	ClientCPUCores          float64                 `json:"client_cpu_cores_median"`
	SubjectCPUCores         float64                 `json:"subject_cpu_cores_median"`
	SubjectCPUSecondsGiB    float64                 `json:"subject_cpu_seconds_per_gib_median,omitempty"`
	SubjectRSSBytes         float64                 `json:"subject_rss_bytes_median,omitempty"`
	SubjectPSSBytes         float64                 `json:"subject_pss_bytes_median,omitempty"`
	SubjectUSSBytes         float64                 `json:"subject_uss_bytes_median,omitempty"`
	SubjectBPFMemlockBytes  float64                 `json:"subject_bpf_map_memlock_bytes_median,omitempty"`
	SystemContextSwitches   float64                 `json:"system_context_switches_per_second_median,omitempty"`
	CPUIdleTransitions      float64                 `json:"cpu_idle_transitions_per_second_median,omitempty"`
	WakeupSourceEvents      float64                 `json:"wakeup_source_events_per_second_median,omitempty"`
	WakeupCount             float64                 `json:"wakeup_count_per_second_median,omitempty"`
	RelativeRawPercent      float64                 `json:"relative_raw_percent,omitempty"`
	RelativeDirectPercent   float64                 `json:"relative_direct_percent,omitempty"`
	Statistics              map[string]Distribution `json:"statistics,omitempty"`
}

type Distribution struct {
	Samples int     `json:"samples"`
	Median  float64 `json:"median"`
	Q1      float64 `json:"q1"`
	Q3      float64 `json:"q3"`
	MAD     float64 `json:"mad"`
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

type caseValues struct {
	ops, success, bits, clientCPU, subjectCPU, cpuGiB, rss, pss, uss, bpf []float64
	contextSwitches, idleTransitions, wakeupEvents, wakeupCount           []float64
	latency, connectLatency, applicationLatency                           []int64
	valid, invalid                                                        int
}

func Build(root string, matrix protocol.MatrixConfig, state protocol.MatrixState) (Summary, error) {
	result := Summary{ProtocolVersion: protocol.Version, MatrixID: matrix.MatrixID}
	caseConfigs := make(map[string]protocol.Config)
	for _, config := range matrix.Cases {
		caseConfigs[config.RunID] = config
	}
	loaded := make(map[string]protocol.Repetition)
	control := make(map[int]map[string]float64)
	var errs []error
	incomplete := 0
	for _, job := range state.Jobs {
		if !job.Complete {
			incomplete++
			continue
		}
		resultPath, pathErr := ownedResultPath(root, job.Result)
		if pathErr != nil {
			errs = append(errs, pathErr)
			continue
		}
		repetition, decodeErr := protocol.DecodeRepetition(resultPath)
		if decodeErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", job.ID, decodeErr))
			continue
		}
		loaded[job.ID] = repetition
		if job.Control != "" && repetition.Validity.Valid && matrix.RawControl != nil {
			if control[job.Block] == nil {
				control[job.Block] = make(map[string]float64)
			}
			control[job.Block][job.Control] = deliveredBitsPerSecond(repetition, *matrix.RawControl)
		}
	}
	if incomplete > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("matrix has %d incomplete jobs", incomplete))
	}
	invalidBlocks := evaluateControls(&result, matrix, control)
	byCase := make(map[string]*caseValues)
	for _, job := range state.Jobs {
		repetition, exists := loaded[job.ID]
		if !exists || job.Control != "" || job.Warmup || repetition.Warmup {
			continue
		}
		config, exists := caseConfigs[job.CaseID]
		if !exists {
			errs = append(errs, fmt.Errorf("missing config for case %s", job.CaseID))
			continue
		}
		value := byCase[job.CaseID]
		if value == nil {
			value = &caseValues{}
			byCase[job.CaseID] = value
		}
		if invalidBlocks[job.Block] || !repetition.Validity.Valid {
			value.invalid++
			continue
		}
		appendRepetition(value, repetition, config)
	}
	caseKeys := make(map[string]string)
	baselines := make(map[string]map[protocol.SubjectKind]float64)
	for _, config := range matrix.Cases {
		item := summarizeCase(config, byCase[config.RunID])
		key := workloadKey(config.Workload)
		caseKeys[config.RunID] = key
		if baselines[key] == nil {
			baselines[key] = make(map[protocol.SubjectKind]float64)
		}
		baselines[key][config.Subject.Kind] = item.DeliveredBitsPerSecond
		result.Cases = append(result.Cases, item)
	}
	for index := range result.Cases {
		item := &result.Cases[index]
		baseline := baselines[caseKeys[item.CaseID]]
		if raw := baseline[protocol.SubjectRaw]; raw > 0 {
			item.RelativeRawPercent = item.DeliveredBitsPerSecond / raw * 100
		}
		if direct := baseline[protocol.SubjectDirect]; direct > 0 {
			item.RelativeDirectPercent = item.DeliveredBitsPerSecond / direct * 100
		}
	}
	return result, errors.Join(errs...)
}

func evaluateControls(result *Summary, matrix protocol.MatrixConfig, control map[int]map[string]float64) map[int]bool {
	invalid := make(map[int]bool)
	if matrix.RawControl == nil {
		return invalid
	}
	for block := 0; block < maxBlocks(matrix.Cases); block++ {
		pair := control[block]
		if pair == nil || pair["before"] <= 0 || pair["after"] <= 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("block %d is missing a valid raw control pair; measured jobs in this block are excluded", block))
			invalid[block] = true
			continue
		}
		percent := math.Abs(pair["after"]-pair["before"]) / pair["before"] * 100
		drift := ControlDrift{Block: block, Before: pair["before"], After: pair["after"], Percent: percent, Valid: percent <= 5}
		result.RawControlDrift = append(result.RawControlDrift, drift)
		if !drift.Valid {
			result.Warnings = append(result.Warnings, fmt.Sprintf("block %d raw throughput drift %.2f%% exceeds 5%%; measured jobs in this block are excluded", block, percent))
			invalid[block] = true
		}
	}
	return invalid
}

func appendRepetition(value *caseValues, repetition protocol.Repetition, config protocol.Config) {
	value.valid++
	if rateDuration := rateDurationNS(repetition, config); rateDuration > 0 {
		value.ops = append(value.ops, float64(repetition.Counters.Operations)*1e9/float64(rateDuration))
		attempts := repetition.Counters.Operations + repetition.Counters.Failed + repetition.Counters.Lost
		if attempts > 0 {
			value.success = append(value.success, float64(repetition.Counters.Operations)/float64(attempts)*100)
		}
		value.bits = append(value.bits, deliveredBitsPerSecond(repetition, config))
		value.clientCPU = append(value.clientCPU, float64(repetition.Resources.ClientRunNanoseconds)/float64(repetition.DurationNS))
		value.subjectCPU = append(value.subjectCPU, float64(repetition.Resources.SubjectRunNanoseconds)/float64(repetition.DurationNS))
		seconds := float64(repetition.DurationNS) / 1e9
		value.contextSwitches = append(value.contextSwitches, float64(repetition.Resources.SystemContextSwitches)/seconds)
		if len(repetition.Resources.CPUIdleUsage) > 0 {
			value.idleTransitions = append(value.idleTransitions, float64(sumUint64Map(repetition.Resources.CPUIdleUsage))/seconds)
		}
		if len(repetition.Resources.WakeupSources) > 0 {
			var wakeupEvents uint64
			var wakeupCount uint64
			for _, counters := range repetition.Resources.WakeupSources {
				wakeupEvents += counters.EventCount
				wakeupCount += counters.WakeupCount
			}
			value.wakeupEvents = append(value.wakeupEvents, float64(wakeupEvents)/seconds)
			value.wakeupCount = append(value.wakeupCount, float64(wakeupCount)/seconds)
		}
		if delivered := deliveredBytes(repetition, config); delivered > 0 {
			value.cpuGiB = append(value.cpuGiB, float64(repetition.Resources.SubjectRunNanoseconds)/1e9/(float64(delivered)/(1<<30)))
		}
	}
	value.rss = append(value.rss, float64(repetition.Resources.SubjectRSSBytes))
	value.pss = append(value.pss, float64(repetition.Resources.SubjectPSSBytes))
	value.uss = append(value.uss, float64(repetition.Resources.SubjectUSSBytes))
	value.bpf = append(value.bpf, float64(repetition.Resources.SubjectBPFMapMemlockBytes))
	value.latency = append(value.latency, repetition.LatencyNS...)
	value.connectLatency = append(value.connectLatency, repetition.ConnectLatencyNS...)
	value.applicationLatency = append(value.applicationLatency, repetition.ApplicationLatencyNS...)
}

func summarizeCase(config protocol.Config, value *caseValues) CaseSummary {
	item := CaseSummary{CaseID: config.RunID, Subject: config.Subject.Kind}
	if value == nil {
		return item
	}
	item.ValidRepetitions, item.InvalidRepetitions = value.valid, value.invalid
	item.OperationsPerSecond = median(value.ops)
	item.SuccessPercent = median(value.success)
	item.DeliveredBitsPerSecond = median(value.bits)
	item.ClientCPUCores = median(value.clientCPU)
	item.SubjectCPUCores = median(value.subjectCPU)
	item.SubjectCPUSecondsGiB = median(value.cpuGiB)
	item.SubjectRSSBytes = median(value.rss)
	item.SubjectPSSBytes = median(value.pss)
	item.SubjectUSSBytes = median(value.uss)
	item.SubjectBPFMemlockBytes = median(value.bpf)
	item.SystemContextSwitches = median(value.contextSwitches)
	item.CPUIdleTransitions = median(value.idleTransitions)
	item.WakeupSourceEvents = median(value.wakeupEvents)
	item.WakeupCount = median(value.wakeupCount)
	item.LatencyP50NS = percentile(value.latency, 0.50)
	item.LatencyP95NS = percentile(value.latency, 0.95)
	item.LatencyP99NS = percentile(value.latency, 0.99)
	item.LatencyP999NS = percentile(value.latency, 0.999)
	item.ConnectLatencyP50NS = percentile(value.connectLatency, 0.50)
	item.ConnectLatencyP95NS = percentile(value.connectLatency, 0.95)
	item.ConnectLatencyP99NS = percentile(value.connectLatency, 0.99)
	item.ApplicationLatencyP50NS = percentile(value.applicationLatency, 0.50)
	item.ApplicationLatencyP95NS = percentile(value.applicationLatency, 0.95)
	item.ApplicationLatencyP99NS = percentile(value.applicationLatency, 0.99)
	item.Statistics = map[string]Distribution{
		"operations_per_second":              distribution(value.ops),
		"success_percent":                    distribution(value.success),
		"delivered_bits_per_second":          distribution(value.bits),
		"client_cpu_cores":                   distribution(value.clientCPU),
		"subject_cpu_cores":                  distribution(value.subjectCPU),
		"subject_cpu_seconds_per_gib":        distribution(value.cpuGiB),
		"subject_rss_bytes":                  distribution(value.rss),
		"subject_pss_bytes":                  distribution(value.pss),
		"subject_uss_bytes":                  distribution(value.uss),
		"subject_bpf_map_memlock_bytes":      distribution(value.bpf),
		"system_context_switches_per_second": distribution(value.contextSwitches),
	}
	addDistribution(item.Statistics, "cpu_idle_transitions_per_second", value.idleTransitions)
	addDistribution(item.Statistics, "wakeup_source_events_per_second", value.wakeupEvents)
	addDistribution(item.Statistics, "wakeup_count_per_second", value.wakeupCount)
	return item
}

func Markdown(summary Summary) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "# Matrix summary: %s\n\n", summary.MatrixID)
	output.WriteString("Only non-warmup repetitions with `validity.valid=true` from raw-control-valid blocks are included. Rates and memory are medians.\n\n")
	output.WriteString("| Case | Subject | Valid | Invalid | Ops/s | Success % | Mbit/s | Raw % | p50 ms | p95 ms | p99 ms | Client CPU | Subject CPU | Subject PSS MiB | BPF map MiB |\n")
	output.WriteString("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	for _, item := range summary.Cases {
		fmt.Fprintf(&output, "| %s | %s | %d | %d | %.2f | %.3f | %.2f | %.1f | %.3f | %.3f | %.3f | %.3f | %.3f | %.2f | %.2f |\n",
			item.CaseID, item.Subject, item.ValidRepetitions, item.InvalidRepetitions, item.OperationsPerSecond,
			item.SuccessPercent, item.DeliveredBitsPerSecond/1e6, item.RelativeRawPercent, float64(item.LatencyP50NS)/1e6,
			float64(item.LatencyP95NS)/1e6, float64(item.LatencyP99NS)/1e6, item.ClientCPUCores,
			item.SubjectCPUCores, item.SubjectPSSBytes/(1<<20), item.SubjectBPFMemlockBytes/(1<<20))
	}
	shortPhases := false
	for _, item := range summary.Cases {
		if item.ConnectLatencyP95NS > 0 || item.ApplicationLatencyP95NS > 0 {
			if !shortPhases {
				output.WriteString("\n## TCP short phases\n\n")
				output.WriteString("| Case | Connect p50 ms | Connect p95 ms | Connect p99 ms | Application p50 ms | Application p95 ms | Application p99 ms |\n")
				output.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n")
				shortPhases = true
			}
			fmt.Fprintf(&output, "| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |\n",
				item.CaseID,
				float64(item.ConnectLatencyP50NS)/1e6,
				float64(item.ConnectLatencyP95NS)/1e6,
				float64(item.ConnectLatencyP99NS)/1e6,
				float64(item.ApplicationLatencyP50NS)/1e6,
				float64(item.ApplicationLatencyP95NS)/1e6,
				float64(item.ApplicationLatencyP99NS)/1e6,
			)
		}
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
	duration := rateDurationNS(repetition, config)
	if duration <= 0 {
		return 0
	}
	return float64(deliveredBytes(repetition, config)) * 8 * 1e9 / float64(duration)
}

func rateDurationNS(repetition protocol.Repetition, config protocol.Config) int64 {
	if config.Workload.Mode == protocol.ModePPS && repetition.WorkloadTiming != nil && repetition.WorkloadTiming.ActiveDurationNS > 0 {
		return repetition.WorkloadTiming.ActiveDurationNS
	}
	return repetition.DurationNS
}

func workloadKey(workload protocol.WorkloadConfig) string {
	return fmt.Sprintf("%s/%s/%s/%d/%d/%d/%d/%d/%d", workload.Protocol, workload.Mode, workload.UDPSocketMode, workload.PayloadBytes,
		workload.Requests, workload.DurationMS, workload.Connections, workload.Flows, workload.OfferedPPS)
}

func sumUint64Map(values map[string]uint64) uint64 {
	var result uint64
	for _, value := range values {
		result += value
	}
	return result
}

func addDistribution(target map[string]Distribution, name string, values []float64) {
	if len(values) > 0 {
		target[name] = distribution(values)
	}
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

func distribution(values []float64) Distribution {
	if len(values) == 0 {
		return Distribution{}
	}
	values = slices.Clone(values)
	slices.Sort(values)
	medianValue := sortedQuantile(values, 0.5)
	deviations := make([]float64, len(values))
	for index, value := range values {
		deviations[index] = math.Abs(value - medianValue)
	}
	slices.Sort(deviations)
	return Distribution{
		Samples: len(values), Median: medianValue, Q1: sortedQuantile(values, 0.25),
		Q3: sortedQuantile(values, 0.75), MAD: sortedQuantile(deviations, 0.5),
	}
}

func sortedQuantile(values []float64, quantile float64) float64 {
	if len(values) == 1 {
		return values[0]
	}
	position := quantile * float64(len(values)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return values[lower]
	}
	weight := position - float64(lower)
	return values[lower]*(1-weight) + values[upper]*weight
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
