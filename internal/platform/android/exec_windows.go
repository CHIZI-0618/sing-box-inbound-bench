//go:build windows

package android

import (
	"context"
	"os/exec"
	"syscall"
)

func newADBCommand(ctx context.Context, binary string, arguments ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, binary, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	return command
}
