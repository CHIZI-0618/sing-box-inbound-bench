package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type protoUint64 uint64

func (v *protoUint64) UnmarshalJSON(content []byte) error {
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return errors.New("empty protobuf integer")
	}
	if content[0] == '"' {
		var value string
		if err := json.Unmarshal(content, &value); err != nil {
			return err
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		*v = protoUint64(parsed)
		return err
	}
	parsed, err := strconv.ParseUint(string(content), 10, 64)
	*v = protoUint64(parsed)
	return err
}

type diagnosticsEnvelope struct {
	Inbounds      []ebpfInboundDiagnostics `json:"inbounds"`
	KernelRuntime json.RawMessage          `json:"kernelRuntime"`
}

type ebpfInboundDiagnostics struct {
	Tag                   string                      `json:"tag"`
	State                 string                      `json:"state"`
	LocalEnabled          bool                        `json:"localEnabled"`
	LocalDataPlane        string                      `json:"localDataPlane"`
	LastError             string                      `json:"lastError"`
	RecoveryPending       bool                        `json:"recoveryPending"`
	RecoveryUnrecoverable bool                        `json:"recoveryUnrecoverable"`
	Attachments           []ebpfAttachmentDiagnostics `json:"attachments"`
	Counters              ebpfFailureCounters         `json:"counters"`
	UDPNAT                ebpfUDPNATDiagnostics       `json:"udpNAT"`
}

type ebpfAttachmentDiagnostics struct {
	InterfaceName string `json:"interfaceName"`
	Role          string `json:"role"`
	Mechanism     string `json:"mechanism"`
}

type ebpfFailureCounters struct {
	AssignmentLookupFailures      protoUint64 `json:"assignmentLookupFailures"`
	TCSocketLookupFailures        protoUint64 `json:"tcSocketLookupFailures"`
	TCSKAssignFailures            protoUint64 `json:"tcSKAssignFailures"`
	TCAssignmentUpdateFailures    protoUint64 `json:"tcAssignmentUpdateFailures"`
	TokenReservationFailures      protoUint64 `json:"tokenReservationFailures"`
	RewriteFailures               protoUint64 `json:"rewriteFailures"`
	SharedReconcileFailures       protoUint64 `json:"sharedReconcileFailures"`
	RecoveryAttempts              protoUint64 `json:"recoveryAttempts"`
	RecoveryFailures              protoUint64 `json:"recoveryFailures"`
	FakeIPICMPRewriteFailureDrops protoUint64 `json:"fakeIPICMPRewriteFailureDrops"`
}

type ebpfUDPNATDiagnostics struct {
	CapacityEvictions              protoUint64 `json:"capacityEvictions"`
	QueueDrops                     protoUint64 `json:"queueDrops"`
	PendingReleaseCapacityRejected protoUint64 `json:"pendingReleaseCapacityRejected"`
	ReleaseNotificationDrops       protoUint64 `json:"releaseNotificationDrops"`
}

func (m *Managed) ObserveRuntimeDiagnostics(ctx context.Context) (json.RawMessage, error) {
	observation, _, err := m.observeEBPFOnce(ctx)
	return observation.Data, err
}

func (m *Managed) ValidateRuntimeDiagnostics(beforeData, afterData json.RawMessage) error {
	before, err := decodeBenchmarkInbound(beforeData)
	if err != nil {
		return fmt.Errorf("decode eBPF diagnostics before measurement: %w", err)
	}
	after, err := decodeBenchmarkInbound(afterData)
	if err != nil {
		return fmt.Errorf("decode eBPF diagnostics after measurement: %w", err)
	}
	valid, message := validateEBPFInbound(after, m.Config.Subject)
	if !valid {
		return errors.New(message)
	}
	if after.RecoveryPending || after.RecoveryUnrecoverable {
		return fmt.Errorf("eBPF recovery state changed during measurement: pending=%t unrecoverable=%t", after.RecoveryPending, after.RecoveryUnrecoverable)
	}
	if after.LastError != "" && after.LastError != before.LastError {
		return fmt.Errorf("eBPF runtime reported a new error during measurement: %s", after.LastError)
	}
	return validateFailureCounterDeltas(before, after)
}

func decodeDiagnostics(data []byte) (diagnosticsEnvelope, error) {
	var diagnostics diagnosticsEnvelope
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		return diagnosticsEnvelope{}, err
	}
	return diagnostics, nil
}

func decodeBenchmarkInbound(data []byte) (ebpfInboundDiagnostics, error) {
	diagnostics, err := decodeDiagnostics(data)
	if err != nil {
		return ebpfInboundDiagnostics{}, err
	}
	for _, inbound := range diagnostics.Inbounds {
		if inbound.Tag == "benchmark-ebpf-in" {
			return inbound, nil
		}
	}
	return ebpfInboundDiagnostics{}, errors.New("benchmark eBPF inbound missing from diagnostics")
}

func validateEBPFDiagnostics(data []byte, config protocol.SubjectConfig) (bool, string, error) {
	inbound, err := decodeBenchmarkInbound(data)
	if err != nil {
		return false, "", err
	}
	valid, message := validateEBPFInbound(inbound, config)
	return valid, message, nil
}

func validateEBPFInbound(inbound ebpfInboundDiagnostics, config protocol.SubjectConfig) (bool, string) {
	wantPlane := "tc"
	if config.Kind == protocol.SubjectEBPFCgroup {
		wantPlane = "cgroup"
	}
	if inbound.State != "normal" || !inbound.LocalEnabled || inbound.LocalDataPlane != wantPlane {
		return false, fmt.Sprintf("runtime state=%s local=%t plane=%s", inbound.State, inbound.LocalEnabled, inbound.LocalDataPlane)
	}
	for _, attachment := range inbound.Attachments {
		if attachment.Role != "local" {
			continue
		}
		if wantPlane == "cgroup" {
			if attachment.Mechanism == "cgroup" && filepath.Clean(attachment.InterfaceName) == filepath.Clean(config.CgroupPath) {
				return true, ""
			}
			continue
		}
		if attachment.Mechanism != "" && attachment.Mechanism != "cgroup" && (config.OutboundInterface == "" || attachment.InterfaceName == config.OutboundInterface) {
			return true, ""
		}
	}
	return false, "no matching local attachment"
}

func validateFailureCounterDeltas(before, after ebpfInboundDiagnostics) error {
	beforeCounters := map[string]uint64{
		"assignment_lookup_failures":                uint64(before.Counters.AssignmentLookupFailures),
		"tc_socket_lookup_failures":                 uint64(before.Counters.TCSocketLookupFailures),
		"tc_sk_assign_failures":                     uint64(before.Counters.TCSKAssignFailures),
		"tc_assignment_update_failures":             uint64(before.Counters.TCAssignmentUpdateFailures),
		"token_reservation_failures":                uint64(before.Counters.TokenReservationFailures),
		"rewrite_failures":                          uint64(before.Counters.RewriteFailures),
		"shared_reconcile_failures":                 uint64(before.Counters.SharedReconcileFailures),
		"recovery_attempts":                         uint64(before.Counters.RecoveryAttempts),
		"recovery_failures":                         uint64(before.Counters.RecoveryFailures),
		"fake_ip_icmp_rewrite_failure_drops":        uint64(before.Counters.FakeIPICMPRewriteFailureDrops),
		"udp_nat.capacity_evictions":                uint64(before.UDPNAT.CapacityEvictions),
		"udp_nat.queue_drops":                       uint64(before.UDPNAT.QueueDrops),
		"udp_nat.pending_release_capacity_rejected": uint64(before.UDPNAT.PendingReleaseCapacityRejected),
		"udp_nat.release_notification_drops":        uint64(before.UDPNAT.ReleaseNotificationDrops),
	}
	afterCounters := map[string]uint64{
		"assignment_lookup_failures":                uint64(after.Counters.AssignmentLookupFailures),
		"tc_socket_lookup_failures":                 uint64(after.Counters.TCSocketLookupFailures),
		"tc_sk_assign_failures":                     uint64(after.Counters.TCSKAssignFailures),
		"tc_assignment_update_failures":             uint64(after.Counters.TCAssignmentUpdateFailures),
		"token_reservation_failures":                uint64(after.Counters.TokenReservationFailures),
		"rewrite_failures":                          uint64(after.Counters.RewriteFailures),
		"shared_reconcile_failures":                 uint64(after.Counters.SharedReconcileFailures),
		"recovery_attempts":                         uint64(after.Counters.RecoveryAttempts),
		"recovery_failures":                         uint64(after.Counters.RecoveryFailures),
		"fake_ip_icmp_rewrite_failure_drops":        uint64(after.Counters.FakeIPICMPRewriteFailureDrops),
		"udp_nat.capacity_evictions":                uint64(after.UDPNAT.CapacityEvictions),
		"udp_nat.queue_drops":                       uint64(after.UDPNAT.QueueDrops),
		"udp_nat.pending_release_capacity_rejected": uint64(after.UDPNAT.PendingReleaseCapacityRejected),
		"udp_nat.release_notification_drops":        uint64(after.UDPNAT.ReleaseNotificationDrops),
	}
	var changed []error
	for name, beforeValue := range beforeCounters {
		afterValue := afterCounters[name]
		if afterValue < beforeValue {
			changed = append(changed, fmt.Errorf("%s moved backwards (%d -> %d)", name, beforeValue, afterValue))
		} else if afterValue > beforeValue {
			changed = append(changed, fmt.Errorf("%s increased by %d", name, afterValue-beforeValue))
		}
	}
	if len(changed) > 0 {
		return fmt.Errorf("eBPF failure counters changed during measurement: %w", errors.Join(changed...))
	}
	return nil
}
