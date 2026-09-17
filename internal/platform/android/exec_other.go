//go:build !windows

package android

import (
	"context"
	"os/exec"
)

func newADBCommand(ctx context.Context, binary string, arguments ...string) *exec.Cmd {
	return exec.CommandContext(ctx, binary, arguments...)
}
