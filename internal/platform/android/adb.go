package android

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
)

type Command struct {
	Arguments []string `json:"arguments"`
	Mutation  bool     `json:"mutation"`
	Resource  string   `json:"resource,omitempty"`
}

type Executor interface {
	Run(context.Context, ...string) ([]byte, error)
}

type OSExecutor struct{ Binary string }

func (e OSExecutor) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	binary := e.Binary
	if binary == "" {
		binary = "adb"
	}
	return exec.CommandContext(ctx, binary, arguments...).CombinedOutput()
}

type Plan struct {
	Serial   string
	DryRun   bool
	Commands []Command
	Executor Executor
}

func (p *Plan) Execute(ctx context.Context) ([][]byte, error) {
	if p.Executor == nil && !p.DryRun {
		return nil, errors.New("ADB executor is required outside dry-run")
	}
	results := make([][]byte, 0, len(p.Commands))
	for _, command := range p.Commands {
		arguments := make([]string, 0, len(command.Arguments)+2)
		if p.Serial != "" {
			arguments = append(arguments, "-s", p.Serial)
		}
		arguments = append(arguments, command.Arguments...)
		if p.DryRun {
			results = append(results, nil)
			continue
		}
		output, err := p.Executor.Run(ctx, arguments...)
		results = append(results, output)
		if err != nil {
			return results, fmt.Errorf("adb %s: %w", strings.Join(arguments, " "), err)
		}
	}
	return results, nil
}

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func RemoteRunDirectory(root, runID string) (string, error) {
	if root == "" || !strings.HasPrefix(root, "/") || !runIDPattern.MatchString(runID) {
		return "", errors.New("invalid Android run directory")
	}
	root = path.Clean(root)
	if root != "/data/local/tmp/sing-box" && !strings.HasPrefix(root, "/data/local/tmp/sing-box/") {
		return "", errors.New("Android benchmark root must stay under /data/local/tmp/sing-box")
	}
	return path.Join(root, "inbound-bench-"+runID), nil
}

// BenchmarkProcessPlan describes only benchmark-owned files and processes.
// It intentionally does not stop the user's production service; production
// manager integration is a separate, explicit transaction.
func BenchmarkProcessPlan(remoteRoot, runID, binaryLocalPath string) (Plan, error) {
	directory, err := RemoteRunDirectory(remoteRoot, runID)
	if err != nil {
		return Plan{}, err
	}
	remoteBinary := path.Join(directory, "inbound-bench")
	return Plan{Commands: []Command{
		{Arguments: []string{"shell", "mkdir", "-p", "--", directory}, Mutation: true, Resource: directory},
		{Arguments: []string{"push", binaryLocalPath, remoteBinary}, Mutation: true, Resource: remoteBinary},
		{Arguments: []string{"shell", "chmod", "0700", "--", remoteBinary}, Mutation: true, Resource: remoteBinary},
	}}, nil
}

func CleanupPlan(remoteRoot, runID string, ownedResources []string) (Plan, error) {
	directory, err := RemoteRunDirectory(remoteRoot, runID)
	if err != nil {
		return Plan{}, err
	}
	for _, resource := range ownedResources {
		if resource != directory && !strings.HasPrefix(path.Clean(resource), directory+"/") {
			return Plan{}, fmt.Errorf("refusing to clean unowned resource %q", resource)
		}
	}
	resources := slices.Clone(ownedResources)
	slices.SortFunc(resources, func(a, b string) int { return len(b) - len(a) })
	commands := make([]Command, 0, len(resources))
	for _, resource := range resources {
		commands = append(commands, Command{Arguments: []string{"shell", "rm", "-rf", "--", resource}, Mutation: true, Resource: resource})
	}
	return Plan{Commands: commands}, nil
}
