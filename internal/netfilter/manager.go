package netfilter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
	"strconv"
	"strings"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Kind string

const (
	Redirect Kind = "redirect"
	TProxy   Kind = "tproxy"
)

type Config struct {
	Kind           Kind
	RunID          string
	Target         netip.AddrPort
	Listen         netip.AddrPort
	WorkerUID      uint32
	Protocol       string
	FirewallBinary string
	IPBinary       string
	Mark           uint32
	RouteTable     int
	RulePriority   int
}

type command struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

type chainCounters struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Observation struct {
	Family   string                   `json:"family"`
	Chains   map[string]chainCounters `json:"chains"`
	Commands []command                `json:"commands,omitempty"`
}

type undo struct {
	command
	done bool
}

// Manager owns only run-scoped chains and exact policy-routing entries. Every
// successful mutation immediately records its inverse, so partial setup can be
// rolled back without flushing or replacing host state.
type Manager struct {
	config      Config
	runner      Runner
	familyFlag  string
	chainOut    string
	chainPre    string
	undo        []undo
	commands    []command
	snapshotted bool
}

func New(config Config, runner Runner) (*Manager, error) {
	if runner == nil {
		return nil, errors.New("netfilter runner is required")
	}
	if config.Kind != Redirect && config.Kind != TProxy {
		return nil, fmt.Errorf("unsupported netfilter kind %q", config.Kind)
	}
	if !config.Target.IsValid() || !config.Listen.IsValid() || config.Target.Addr().Is4() != config.Listen.Addr().Is4() {
		return nil, errors.New("target and listener must be valid addresses in the same family")
	}
	if config.Protocol != "tcp" && config.Protocol != "udp" {
		return nil, fmt.Errorf("unsupported protocol %q", config.Protocol)
	}
	if config.Kind == Redirect && config.Protocol != "tcp" {
		return nil, errors.New("REDIRECT benchmark only supports TCP")
	}
	if config.FirewallBinary == "" {
		config.FirewallBinary = "iptables"
		if config.Target.Addr().Is6() {
			config.FirewallBinary = "ip6tables"
		}
	}
	if config.IPBinary == "" {
		config.IPBinary = "ip"
	}
	family := "-4"
	if config.Target.Addr().Is6() {
		family = "-6"
	}
	hash := fmt.Sprintf("%08X", crc32.ChecksumIEEE([]byte(config.RunID)))
	m := &Manager{config: config, runner: runner, familyFlag: family}
	if config.Kind == Redirect {
		m.chainOut = "SBI_R_" + hash
	} else {
		m.chainOut = "SBI_O_" + hash
		m.chainPre = "SBI_P_" + hash
	}
	return m, nil
}

func (m *Manager) Snapshot(ctx context.Context) error {
	table := m.table()
	if _, err := m.run(ctx, m.config.FirewallBinary, "-w", "-t", table, "-S"); err != nil {
		return fmt.Errorf("access %s table: %w", table, err)
	}
	for _, chain := range m.chains() {
		if _, err := m.run(ctx, m.config.FirewallBinary, "-w", "-t", table, "-S", chain); err == nil {
			return fmt.Errorf("owned chain name already exists: %s", chain)
		}
	}
	if m.config.Kind == TProxy {
		if _, err := m.run(ctx, m.config.IPBinary, "-Version"); err != nil {
			return fmt.Errorf("access ip tool: %w", err)
		}
		output, err := m.run(ctx, m.config.IPBinary, m.familyFlag, "rule", "show", "priority", strconv.Itoa(m.config.RulePriority))
		if err != nil {
			return fmt.Errorf("inspect policy rule priority: %w", err)
		}
		if strings.TrimSpace(string(output)) != "" {
			return fmt.Errorf("policy rule priority %d is already in use", m.config.RulePriority)
		}
		output, err = m.run(ctx, m.config.IPBinary, m.familyFlag, "route", "show", "table", strconv.Itoa(m.config.RouteTable))
		if err != nil {
			return fmt.Errorf("inspect route table: %w", err)
		}
		if strings.TrimSpace(string(output)) != "" {
			return fmt.Errorf("route table %d is already in use", m.config.RouteTable)
		}
	}
	m.snapshotted = true
	return nil
}

func (m *Manager) Install(ctx context.Context) error {
	if !m.snapshotted {
		return errors.New("netfilter snapshot was not completed")
	}
	if m.config.Kind == Redirect {
		return m.installRedirect(ctx)
	}
	return m.installTProxy(ctx)
}

func (m *Manager) installRedirect(ctx context.Context) error {
	table := "nat"
	if err := m.mutate(ctx, m.config.FirewallBinary,
		[]string{"-w", "-t", table, "-N", m.chainOut},
		[]string{"-w", "-t", table, "-X", m.chainOut}); err != nil {
		return err
	}
	rule := []string{"-p", "tcp", "-d", m.targetPrefix(), "--dport", strconv.Itoa(int(m.config.Target.Port())), "-j", "REDIRECT", "--to-ports", strconv.Itoa(int(m.config.Listen.Port()))}
	if err := m.appendRule(ctx, table, m.chainOut, rule); err != nil {
		return err
	}
	jump := []string{"-m", "owner", "--uid-owner", strconv.FormatUint(uint64(m.config.WorkerUID), 10), "-p", "tcp", "-d", m.targetPrefix(), "--dport", strconv.Itoa(int(m.config.Target.Port())), "-j", m.chainOut}
	return m.insertJump(ctx, table, "OUTPUT", jump)
}

func (m *Manager) installTProxy(ctx context.Context) error {
	mark := fmt.Sprintf("0x%x/0xffffffff", m.config.Mark)
	routePrefix := "0.0.0.0/0"
	if m.config.Target.Addr().Is6() {
		routePrefix = "::/0"
	}
	tableID := strconv.Itoa(m.config.RouteTable)
	if err := m.mutate(ctx, m.config.IPBinary,
		[]string{m.familyFlag, "route", "add", "local", routePrefix, "dev", "lo", "table", tableID},
		[]string{m.familyFlag, "route", "del", "local", routePrefix, "dev", "lo", "table", tableID}); err != nil {
		return err
	}
	priority := strconv.Itoa(m.config.RulePriority)
	if err := m.mutate(ctx, m.config.IPBinary,
		[]string{m.familyFlag, "rule", "add", "priority", priority, "fwmark", mark, "lookup", tableID},
		[]string{m.familyFlag, "rule", "del", "priority", priority, "fwmark", mark, "lookup", tableID}); err != nil {
		return err
	}
	for _, chain := range m.chains() {
		if err := m.mutate(ctx, m.config.FirewallBinary,
			[]string{"-w", "-t", "mangle", "-N", chain},
			[]string{"-w", "-t", "mangle", "-X", chain}); err != nil {
			return err
		}
	}
	match := []string{"-p", m.config.Protocol, "-d", m.targetPrefix(), "--dport", strconv.Itoa(int(m.config.Target.Port()))}
	markRule := append(append([]string{}, match...), "-j", "MARK", "--set-xmark", mark)
	if err := m.appendRule(ctx, "mangle", m.chainOut, markRule); err != nil {
		return err
	}
	tproxyRule := append(append([]string{}, match...), "-m", "mark", "--mark", mark, "-j", "TPROXY", "--on-ip", m.config.Listen.Addr().String(), "--on-port", strconv.Itoa(int(m.config.Listen.Port())), "--tproxy-mark", mark)
	if err := m.appendRule(ctx, "mangle", m.chainPre, tproxyRule); err != nil {
		return err
	}
	outputJump := []string{"-m", "owner", "--uid-owner", strconv.FormatUint(uint64(m.config.WorkerUID), 10), "-p", m.config.Protocol, "-d", m.targetPrefix(), "--dport", strconv.Itoa(int(m.config.Target.Port())), "-j", m.chainOut}
	if err := m.insertJump(ctx, "mangle", "OUTPUT", outputJump); err != nil {
		return err
	}
	preJump := []string{"-m", "mark", "--mark", mark, "-p", m.config.Protocol, "-d", m.targetPrefix(), "--dport", strconv.Itoa(int(m.config.Target.Port())), "-j", m.chainPre}
	return m.insertJump(ctx, "mangle", "PREROUTING", preJump)
}

func (m *Manager) appendRule(ctx context.Context, table, chain string, rule []string) error {
	return m.mutate(ctx, m.config.FirewallBinary,
		append([]string{"-w", "-t", table, "-A", chain}, rule...),
		append([]string{"-w", "-t", table, "-D", chain}, rule...))
}

func (m *Manager) insertJump(ctx context.Context, table, chain string, rule []string) error {
	return m.mutate(ctx, m.config.FirewallBinary,
		append([]string{"-w", "-t", table, "-I", chain, "1"}, rule...),
		append([]string{"-w", "-t", table, "-D", chain}, rule...))
}

func (m *Manager) mutate(ctx context.Context, name string, forward, inverse []string) error {
	output, err := m.run(ctx, name, forward...)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(forward, " "), err, strings.TrimSpace(string(output)))
	}
	m.undo = append(m.undo, undo{command: command{Name: name, Args: append([]string(nil), inverse...)}})
	return nil
}

func (m *Manager) Observe(ctx context.Context) ([]byte, error) {
	observation := Observation{Family: m.familyFlag, Chains: make(map[string]chainCounters), Commands: append([]command(nil), m.commands...)}
	for _, chain := range m.chains() {
		output, err := m.run(ctx, m.config.FirewallBinary, "-w", "-t", m.table(), "-L", chain, "-n", "-v", "-x")
		if err != nil {
			return nil, fmt.Errorf("read counters for %s: %w", chain, err)
		}
		observation.Chains[chain] = parseCounters(output)
	}
	return json.Marshal(observation)
}

func (m *Manager) Prove(beforeData, afterData []byte) error {
	var before, after Observation
	if err := json.Unmarshal(beforeData, &before); err != nil {
		return err
	}
	if err := json.Unmarshal(afterData, &after); err != nil {
		return err
	}
	for _, chain := range m.chains() {
		beforeCounter, beforeOK := before.Chains[chain]
		afterCounter, afterOK := after.Chains[chain]
		if !beforeOK || !afterOK || afterCounter.Packets <= beforeCounter.Packets || afterCounter.Bytes <= beforeCounter.Bytes {
			return fmt.Errorf("chain %s counters did not increase", chain)
		}
	}
	return nil
}

func (m *Manager) Cleanup(ctx context.Context) error {
	var errs []error
	for index := len(m.undo) - 1; index >= 0; index-- {
		operation := &m.undo[index]
		if operation.done {
			continue
		}
		output, err := m.run(ctx, operation.Name, operation.Args...)
		if err != nil {
			errs = append(errs, fmt.Errorf("undo %s %s: %w: %s", operation.Name, strings.Join(operation.Args, " "), err, strings.TrimSpace(string(output))))
			continue
		}
		operation.done = true
	}
	return errors.Join(errs...)
}

func (m *Manager) VerifyRestore(context.Context) error {
	for _, operation := range m.undo {
		if !operation.done {
			return errors.New("one or more owned netfilter resources remain")
		}
	}
	return nil
}

func (m *Manager) Commands() ([]byte, error) { return json.MarshalIndent(m.commands, "", "  ") }

func (m *Manager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.commands = append(m.commands, command{Name: name, Args: append([]string(nil), args...)})
	return m.runner.Run(ctx, name, args...)
}

func (m *Manager) chains() []string {
	if m.chainPre == "" {
		return []string{m.chainOut}
	}
	return []string{m.chainOut, m.chainPre}
}

func (m *Manager) table() string {
	if m.config.Kind == Redirect {
		return "nat"
	}
	return "mangle"
}

func (m *Manager) targetPrefix() string {
	bits := 32
	if m.config.Target.Addr().Is6() {
		bits = 128
	}
	return netip.PrefixFrom(m.config.Target.Addr(), bits).String()
}

func parseCounters(output []byte) chainCounters {
	var result chainCounters
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		packets, packetErr := strconv.ParseUint(fields[0], 10, 64)
		bytes, byteErr := strconv.ParseUint(fields[1], 10, 64)
		if packetErr == nil && byteErr == nil {
			result.Packets += packets
			result.Bytes += bytes
		}
	}
	return result
}
