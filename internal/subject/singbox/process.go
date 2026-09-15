package singbox

import (
	"context"
	"io"
	"os"
	"os/exec"
)

type Process interface {
	PID() int
	Signal(os.Signal) error
	Kill() error
	Done() <-chan error
}

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	Start(string, []string, io.Writer, io.Writer) (Process, error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, arguments...).CombinedOutput()
}

func (OSCommandRunner) Start(name string, arguments []string, stdout, stderr io.Writer) (Process, error) {
	command := exec.Command(name, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &osProcess{process: command.Process, done: make(chan error, 1)}
	go func() {
		process.done <- command.Wait()
		close(process.done)
	}()
	return process, nil
}

type osProcess struct {
	process *os.Process
	done    chan error
}

func (p *osProcess) PID() int                      { return p.process.Pid }
func (p *osProcess) Signal(signal os.Signal) error { return p.process.Signal(signal) }
func (p *osProcess) Kill() error                   { return p.process.Kill() }
func (p *osProcess) Done() <-chan error            { return p.done }
