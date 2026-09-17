package subject

import (
	"encoding/json"
	"testing"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

func TestValidateSocketPathEvidence(t *testing.T) {
	uid := uint32(2000)
	makeDetails := func(server string, cgroup bool) json.RawMessage {
		value := map[string]any{
			"identity": protocol.WorkerIdentity{PID: 123, UID: uid, CgroupPath: "/sys/fs/cgroup/bench", CgroupVerified: cgroup},
			"workload": protocol.WorkloadResult{SocketPaths: []protocol.SocketPathEvidence{{Network: "tcp", ClientLocal: "192.0.2.1:1000", ServerObservedPeer: server}}},
		}
		result, _ := json.Marshal(value)
		return result
	}
	if err := ValidateSocketPathEvidence(makeDetails("192.0.2.1:1000", false), false, &uid, ""); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSocketPathEvidence(makeDetails("192.0.2.1:2000", false), false, &uid, ""); err != nil {
		t.Fatalf("rejected raw traffic after source-port translation: %v", err)
	}
	if err := ValidateSocketPathEvidence(makeDetails("192.0.2.2:1000", false), false, &uid, ""); err == nil {
		t.Fatal("accepted a changed raw source address")
	}
	if err := ValidateSocketPathEvidence(makeDetails("192.0.2.1:2000", true), true, &uid, "/sys/fs/cgroup/bench"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSocketPathEvidence(makeDetails("192.0.2.1:1000", true), true, &uid, "/sys/fs/cgroup/bench"); err == nil {
		t.Fatal("accepted an unchanged tuple as redirected traffic")
	}
}
