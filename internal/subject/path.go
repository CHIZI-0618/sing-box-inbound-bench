package subject

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type warmupResult struct {
	Identity protocol.WorkerIdentity `json:"identity"`
	Workload struct {
		SocketPaths []protocol.SocketPathEvidence `json:"socket_paths"`
	} `json:"workload"`
}

func ValidateSocketPathEvidence(details json.RawMessage, redirected bool, workerUID *uint32, cgroupPath string) error {
	var result warmupResult
	if err := json.Unmarshal(details, &result); err != nil {
		return fmt.Errorf("decode worker evidence: %w", err)
	}
	if result.Identity.PID < 1 {
		return errors.New("worker evidence has no PID")
	}
	if workerUID != nil && result.Identity.UID != *workerUID {
		return fmt.Errorf("worker ran as UID %d instead of %d", result.Identity.UID, *workerUID)
	}
	if cgroupPath != "" {
		if !result.Identity.CgroupVerified || filepath.Clean(result.Identity.CgroupPath) != filepath.Clean(cgroupPath) {
			return errors.New("worker cgroup membership was not verified before socket creation")
		}
	}
	if len(result.Workload.SocketPaths) == 0 {
		return errors.New("worker returned no socket tuple evidence")
	}
	for _, path := range result.Workload.SocketPaths {
		client, err := protocol.CanonicalEndpoint(path.ClientLocal)
		if err != nil {
			return fmt.Errorf("invalid client tuple: %w", err)
		}
		server, err := protocol.CanonicalEndpoint(path.ServerObservedPeer)
		if err != nil {
			return fmt.Errorf("invalid server-observed tuple: %w", err)
		}
		if redirected && client == server {
			return fmt.Errorf("%s server observed the worker socket tuple; redirection was not proven", path.Network)
		}
		clientAddress, _ := netip.ParseAddrPort(client)
		serverAddress, _ := netip.ParseAddrPort(server)
		if !redirected && clientAddress.Addr() != serverAddress.Addr() {
			return fmt.Errorf("%s server observed source address %s instead of raw worker address %s", path.Network, serverAddress.Addr(), clientAddress.Addr())
		}
	}
	return nil
}
