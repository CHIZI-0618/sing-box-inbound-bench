package subject

import (
	"context"
	"encoding/json"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

type Observation struct {
	CapturedAt time.Time       `json:"captured_at"`
	Data       json.RawMessage `json:"data,omitempty"`
}

type WarmupEvidence struct {
	Valid   bool            `json:"valid"`
	Token   string          `json:"token,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

type Artifact struct {
	Name      string
	Content   []byte
	Truncated bool
}

// RuntimeDiagnosticsProvider captures subject-specific runtime state outside
// the measured workload interval. Implementations should keep observation
// side effects out of the timed data path.
type RuntimeDiagnosticsProvider interface {
	ObserveRuntimeDiagnostics(context.Context) (json.RawMessage, error)
	ValidateRuntimeDiagnostics(before, after json.RawMessage) error
}

type Subject interface {
	Kind() protocol.SubjectKind
	Preflight(context.Context) error
	Snapshot(context.Context) error
	Setup(context.Context) error
	Start(context.Context) error
	ObservePath(context.Context) (Observation, error)
	ProvePath(context.Context, Observation, Observation, WarmupEvidence) (protocol.PathProof, error)
	Stop(context.Context) error
	Artifacts(context.Context) ([]Artifact, error)
	Cleanup(context.Context) error
	VerifyRestore(context.Context) error
}
