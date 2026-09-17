package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

const (
	packetMagic   = 0x53424955 // SBIU
	packetVersion = 2
	headerSize    = 40
	flagResponse  = 1
	flagProof     = 2
)

type header struct {
	flags    uint8
	run      uint32
	flow     uint32
	sequence uint64
	sentNS   int64
	checksum uint32
}

type Server struct {
	MaxPacket int
}

func (s Server) Serve(ctx context.Context, connection net.PacketConn) error {
	if s.MaxPacket == 0 {
		s.MaxPacket = 65_507
	}
	buffer := make([]byte, s.MaxPacket)
	go func() {
		<-ctx.Done()
		_ = connection.Close()
	}()
	for {
		length, address, err := connection.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		packet := buffer[:length]
		h, valid := parse(packet)
		if !valid || h.flags&flagResponse != 0 {
			continue
		}
		if h.flags&flagProof != 0 {
			observed, encodeErr := protocol.EncodeEndpoint(address)
			if encodeErr != nil {
				return encodeErr
			}
			proofResponse := make([]byte, len(packet)+len(observed))
			copy(proofResponse, packet)
			copy(proofResponse[len(packet):], observed)
			proofResponse[5] |= flagResponse
			binary.BigEndian.PutUint32(proofResponse[32:36], crc32.ChecksumIEEE(proofResponse[headerSize:]))
			binary.BigEndian.PutUint32(proofResponse[36:40], crc32.ChecksumIEEE(proofResponse[:36]))
			if _, err = connection.WriteTo(proofResponse, address); err != nil {
				return err
			}
			continue
		}
		packet[5] |= flagResponse
		binary.BigEndian.PutUint32(packet[36:40], crc32.ChecksumIEEE(packet[:36]))
		if _, err = connection.WriteTo(packet, address); err != nil {
			return err
		}
	}
}

type ClientConfig struct {
	Target       string
	Mode         protocol.WorkloadMode
	PayloadBytes int
	Requests     int
	Duration     time.Duration
	Flows        int
	OfferedPPS   int
	SocketMode   protocol.UDPSocketMode
	Timeout      time.Duration
	RunHash      uint32
	CollectProof bool
}

func Run(ctx context.Context, config ClientConfig) (protocol.Counters, []int64, error) {
	result, err := RunDetailed(ctx, config)
	return result.Counters, result.LatencyNS, err
}

func RunDetailed(ctx context.Context, config ClientConfig) (protocol.WorkloadResult, error) {
	startedAt := time.Now()
	if config.CollectProof && headerSize+config.PayloadBytes+protocol.EncodedEndpointSize > 65_507 {
		return protocol.WorkloadResult{}, errors.New("UDP path proof response exceeds the maximum datagram size")
	}
	if config.Flows < 1 {
		config.Flows = 1
	}
	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Second
	}
	if config.Mode == "" {
		config.Mode = protocol.ModeEcho
	}
	if config.SocketMode == "" {
		config.SocketMode = protocol.UDPSocketConnected
	}
	if config.Mode == protocol.ModePPS {
		return runPPS(ctx, config, startedAt)
	}
	ctx, cancel := deadlineContext(ctx, config.Duration)
	defer cancel()
	var counters atomicCounters
	latencyByFlow := make([][]int64, config.Flows)
	pathsByFlow := make([][]protocol.SocketPathEvidence, config.Flows)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for flow := 0; flow < config.Flows; flow++ {
		workers.Add(1)
		go func(flow int) {
			defer workers.Done()
			<-start
			if err := runEchoFlow(ctx, config, flow, &counters, &latencyByFlow[flow], &pathsByFlow[flow]); err != nil && ctx.Err() == nil {
				counters.setError(err)
			}
		}(flow)
	}
	close(start)
	workers.Wait()
	finishedAt := time.Now()
	return protocol.WorkloadResult{
		Counters: counters.snapshot(), LatencyNS: joinLatencies(latencyByFlow), SocketPaths: joinPathEvidence(pathsByFlow),
		Timing: protocol.WorkloadTiming{StartedAt: startedAt, ActiveDurationNS: finishedAt.Sub(startedAt).Nanoseconds(), FinishedAt: finishedAt},
	}, counters.err()
}

type atomicCounters struct {
	operations      atomic.Uint64
	failed          atomic.Uint64
	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
	lost            atomic.Uint64
	reordered       atomic.Uint64
	corrupt         atomic.Uint64
	once            sync.Once
	firstError      error
}

func (c *atomicCounters) setError(err error) {
	c.failed.Add(1)
	c.once.Do(func() { c.firstError = err })
}

func (c *atomicCounters) err() error { return c.firstError }

func (c *atomicCounters) snapshot() protocol.Counters {
	return protocol.Counters{
		Operations: c.operations.Load(), Failed: c.failed.Load(), BytesSent: c.bytesSent.Load(), BytesReceived: c.bytesReceived.Load(),
		PacketsSent: c.packetsSent.Load(), PacketsReceived: c.packetsReceived.Load(), Lost: c.lost.Load(), Reordered: c.reordered.Load(), Corrupt: c.corrupt.Load(),
	}
}

func runEchoFlow(ctx context.Context, config ClientConfig, flow int, counters *atomicCounters, latencies *[]int64, paths *[]protocol.SocketPathEvidence) error {
	connection, err := dialUDPFlow(ctx, config.Target, config.SocketMode, config.Timeout)
	if err != nil {
		return err
	}
	defer connection.Close()
	packet := make([]byte, headerSize+config.PayloadBytes)
	responseSize := len(packet)
	if config.CollectProof {
		responseSize += protocol.EncodedEndpointSize
	}
	response := make([]byte, responseSize)
	requests := perWorkerRequests(config.Requests, config.Flows, flow)
	var previous uint64
	for completed := 0; requests == 0 || completed < requests; completed++ {
		if ctx.Err() != nil {
			return nil
		}
		sequence := uint64(completed + 1)
		sentAt := time.Now()
		requestHeader := header{run: config.RunHash, flow: uint32(flow), sequence: sequence, sentNS: sentAt.UnixNano()}
		if config.CollectProof && completed == 0 {
			requestHeader.flags |= flagProof
		}
		build(packet, requestHeader)
		if err = connection.SetDeadline(sentAt.Add(config.Timeout)); err != nil {
			return err
		}
		if _, err = connection.Write(packet); err != nil {
			return err
		}
		counters.packetsSent.Add(1)
		counters.bytesSent.Add(uint64(config.PayloadBytes))
		length, readErr := connection.Read(response)
		if readErr != nil {
			if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				counters.lost.Add(1)
				continue
			}
			return readErr
		}
		counters.packetsReceived.Add(1)
		got, valid := parse(response[:length])
		expectedLength := len(packet)
		expectedFlags := uint8(flagResponse)
		if requestHeader.flags&flagProof != 0 {
			expectedLength += protocol.EncodedEndpointSize
			expectedFlags |= flagProof
		}
		if !valid || got.flags != expectedFlags || got.run != config.RunHash || got.flow != uint32(flow) || length != expectedLength {
			counters.corrupt.Add(1)
			continue
		}
		counters.bytesReceived.Add(uint64(config.PayloadBytes))
		if got.sequence <= previous || got.sequence != sequence {
			counters.reordered.Add(1)
			continue
		}
		previous = got.sequence
		if requestHeader.flags&flagProof != 0 {
			serverPeer, decodeErr := protocol.DecodeEndpoint(response[length-protocol.EncodedEndpointSize : length])
			if decodeErr != nil {
				return decodeErr
			}
			clientLocal, canonicalErr := effectiveLocalEndpoint(ctx, connection, config.Target, config.Timeout)
			if canonicalErr != nil {
				return canonicalErr
			}
			*paths = append(*paths, protocol.SocketPathEvidence{Network: "udp", ClientLocal: clientLocal, ServerObservedPeer: serverPeer})
		}
		*latencies = append(*latencies, time.Since(sentAt).Nanoseconds())
		counters.operations.Add(1)
	}
	return nil
}

func effectiveLocalEndpoint(ctx context.Context, connection net.Conn, target string, timeout time.Duration) (string, error) {
	local, err := netip.ParseAddrPort(connection.LocalAddr().String())
	if err != nil {
		return "", err
	}
	if !local.Addr().IsUnspecified() {
		return protocol.CanonicalEndpoint(local.String())
	}
	probe, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", target)
	if err != nil {
		return "", fmt.Errorf("resolve effective unconnected UDP source: %w", err)
	}
	probeLocal, parseErr := netip.ParseAddrPort(probe.LocalAddr().String())
	closeErr := probe.Close()
	if parseErr != nil || closeErr != nil {
		return "", errors.Join(parseErr, closeErr)
	}
	effective := netip.AddrPortFrom(probeLocal.Addr(), local.Port())
	return protocol.CanonicalEndpoint(effective.String())
}

type ppsFlow struct {
	connection net.Conn
	expected   int
	sentAt     []atomic.Int64
	seen       []bool
	latencies  []int64
	previous   uint64
	received   int
}

func runPPS(ctx context.Context, config ClientConfig, startedAt time.Time) (protocol.WorkloadResult, error) {
	totalPackets, err := packetCount(config)
	if err != nil {
		return protocol.WorkloadResult{}, err
	}
	if totalPackets < config.Flows {
		return protocol.WorkloadResult{}, fmt.Errorf("PPS workload has %d packets for %d flows", totalPackets, config.Flows)
	}
	flows := make([]ppsFlow, config.Flows)
	for flow := range flows {
		connection, dialErr := dialUDPFlow(ctx, config.Target, config.SocketMode, config.Timeout)
		if dialErr != nil {
			closePPSFlows(flows)
			return protocol.WorkloadResult{}, dialErr
		}
		expected := perWorkerRequests(totalPackets, config.Flows, flow)
		flows[flow] = ppsFlow{connection: connection, expected: expected, sentAt: make([]atomic.Int64, expected+1), seen: make([]bool, expected+1), latencies: make([]int64, 0, expected)}
	}
	defer closePPSFlows(flows)
	var counters atomicCounters
	clockBase := time.Now()
	offeredDuration, err := packetOffset(totalPackets, config.OfferedPPS)
	if err != nil {
		return protocol.WorkloadResult{}, err
	}
	deadline := clockBase.Add(offeredDuration + config.Timeout)
	var receivers sync.WaitGroup
	receiverErrors := make(chan error, len(flows))
	for flow := range flows {
		if err = flows[flow].connection.SetReadDeadline(deadline); err != nil {
			return protocol.WorkloadResult{}, err
		}
		receivers.Add(1)
		go func(flow int) {
			defer receivers.Done()
			if receiveErr := receivePPSFlow(config, flow, clockBase, &flows[flow], &counters); receiveErr != nil {
				receiverErrors <- receiveErr
			}
		}(flow)
	}
	packet := make([]byte, headerSize+config.PayloadBytes)
	sequences := make([]int, len(flows))
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	for index := 0; index < totalPackets; index++ {
		offset, offsetErr := packetOffset(index, config.OfferedPPS)
		if offsetErr != nil {
			closePPSFlows(flows)
			receivers.Wait()
			return protocol.WorkloadResult{}, offsetErr
		}
		target := clockBase.Add(offset)
		if err = waitUntil(ctx, timer, target); err != nil {
			closePPSFlows(flows)
			receivers.Wait()
			finishedAt := time.Now()
			return protocol.WorkloadResult{Counters: counters.snapshot(), LatencyNS: joinPPSLatencies(flows), Timing: protocol.WorkloadTiming{StartedAt: startedAt, ActiveDurationNS: finishedAt.Sub(startedAt).Nanoseconds(), FinishedAt: finishedAt}}, err
		}
		flow := index % len(flows)
		sequences[flow]++
		sequence := sequences[flow]
		now := time.Now()
		flows[flow].sentAt[sequence].Store(time.Since(clockBase).Nanoseconds() + 1)
		build(packet, header{run: config.RunHash, flow: uint32(flow), sequence: uint64(sequence), sentNS: now.UnixNano()})
		if _, err = flows[flow].connection.Write(packet); err != nil {
			closePPSFlows(flows)
			receivers.Wait()
			finishedAt := time.Now()
			return protocol.WorkloadResult{Counters: counters.snapshot(), LatencyNS: joinPPSLatencies(flows), Timing: protocol.WorkloadTiming{StartedAt: startedAt, ActiveDurationNS: finishedAt.Sub(startedAt).Nanoseconds(), FinishedAt: finishedAt}}, err
		}
		counters.packetsSent.Add(1)
		counters.bytesSent.Add(uint64(config.PayloadBytes))
	}
	activeFinishedAt := time.Now()
	receivers.Wait()
	finishedAt := time.Now()
	close(receiverErrors)
	for receiveErr := range receiverErrors {
		counters.setError(receiveErr)
	}
	for flow := range flows {
		counters.lost.Add(uint64(flows[flow].expected - flows[flow].received))
	}
	return protocol.WorkloadResult{
		Counters: counters.snapshot(), LatencyNS: joinPPSLatencies(flows),
		Timing: protocol.WorkloadTiming{StartedAt: startedAt, SetupDurationNS: clockBase.Sub(startedAt).Nanoseconds(), ActiveDurationNS: activeFinishedAt.Sub(clockBase).Nanoseconds(), DrainDurationNS: finishedAt.Sub(activeFinishedAt).Nanoseconds(), FinishedAt: finishedAt},
	}, counters.err()
}

type unconnectedUDPConn struct {
	net.PacketConn
	target net.Addr
}

func (c *unconnectedUDPConn) Read(buffer []byte) (int, error) {
	length, source, err := c.PacketConn.ReadFrom(buffer)
	if err != nil {
		return 0, err
	}
	if source.String() != c.target.String() {
		return 0, fmt.Errorf("unexpected UDP response source %s, want %s", source, c.target)
	}
	return length, nil
}

func (c *unconnectedUDPConn) Write(buffer []byte) (int, error) {
	return c.PacketConn.WriteTo(buffer, c.target)
}

func (c *unconnectedUDPConn) RemoteAddr() net.Addr { return c.target }

func dialUDPFlow(ctx context.Context, target string, mode protocol.UDPSocketMode, timeout time.Duration) (net.Conn, error) {
	if mode == protocol.UDPSocketConnected {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", target)
	}
	if mode != protocol.UDPSocketUnconnected {
		return nil, fmt.Errorf("unsupported UDP socket mode %q", mode)
	}
	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	listenAddress := "0.0.0.0:0"
	if remote.IP.To4() == nil {
		network = "udp6"
		listenAddress = "[::]:0"
	}
	connection, err := (&net.ListenConfig{}).ListenPacket(ctx, network, listenAddress)
	if err != nil {
		return nil, err
	}
	return &unconnectedUDPConn{PacketConn: connection, target: remote}, nil
}

func receivePPSFlow(config ClientConfig, flow int, clockBase time.Time, state *ppsFlow, counters *atomicCounters) error {
	response := make([]byte, headerSize+config.PayloadBytes)
	for state.received < state.expected {
		length, err := state.connection.Read(response)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		counters.packetsReceived.Add(1)
		if length >= headerSize {
			counters.bytesReceived.Add(uint64(length - headerSize))
		}
		got, valid := parse(response[:length])
		if !valid || got.flags&flagResponse == 0 || got.run != config.RunHash || got.flow != uint32(flow) || got.sequence == 0 || got.sequence > uint64(state.expected) {
			counters.corrupt.Add(1)
			continue
		}
		if state.seen[got.sequence] {
			counters.reordered.Add(1)
			continue
		}
		if state.previous != 0 && got.sequence < state.previous {
			counters.reordered.Add(1)
		}
		if got.sequence > state.previous {
			state.previous = got.sequence
		}
		state.seen[got.sequence] = true
		startedOffset := state.sentAt[got.sequence].Load()
		if startedOffset == 0 {
			counters.corrupt.Add(1)
			continue
		}
		state.latencies = append(state.latencies, time.Since(clockBase).Nanoseconds()-(startedOffset-1))
		state.received++
		counters.operations.Add(1)
	}
	return nil
}

func packetCount(config ClientConfig) (int, error) {
	if config.OfferedPPS < 1 || config.OfferedPPS > 1_000_000_000 {
		return 0, errors.New("offered PPS must be between 1 and 1000000000")
	}
	if config.Requests > 0 {
		return config.Requests, nil
	}
	seconds := config.Duration / time.Second
	remainder := config.Duration % time.Second
	if seconds > time.Duration(math.MaxInt/config.OfferedPPS) {
		return 0, errors.New("PPS packet count overflows int")
	}
	total := int(seconds)*config.OfferedPPS + int(remainder)*config.OfferedPPS/int(time.Second)
	if total < 1 {
		return 0, errors.New("PPS duration is too short for the offered rate")
	}
	return total, nil
}

func packetOffset(index, rate int) (time.Duration, error) {
	if index < 0 || rate < 1 {
		return 0, errors.New("invalid packet schedule")
	}
	seconds := index / rate
	if int64(seconds) > math.MaxInt64/int64(time.Second) {
		return 0, errors.New("PPS schedule exceeds time.Duration")
	}
	return time.Duration(seconds)*time.Second + time.Duration(index%rate)*time.Second/time.Duration(rate), nil
}

func waitUntil(ctx context.Context, timer *time.Timer, target time.Time) error {
	delay := time.Until(target)
	if delay <= 0 {
		return nil
	}
	timer.Reset(delay)
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return ctx.Err()
	}
}

func closePPSFlows(flows []ppsFlow) {
	for flow := range flows {
		if flows[flow].connection != nil {
			_ = flows[flow].connection.Close()
		}
	}
}

func joinPPSLatencies(flows []ppsFlow) []int64 {
	result := make([]int64, 0)
	for flow := range flows {
		result = append(result, flows[flow].latencies...)
	}
	return result
}

func joinLatencies(flows [][]int64) []int64 {
	result := make([]int64, 0)
	for _, values := range flows {
		result = append(result, values...)
	}
	return result
}

func joinPathEvidence(flows [][]protocol.SocketPathEvidence) []protocol.SocketPathEvidence {
	var result []protocol.SocketPathEvidence
	for _, values := range flows {
		result = append(result, values...)
	}
	return result
}

func build(packet []byte, value header) {
	binary.BigEndian.PutUint32(packet[0:4], packetMagic)
	packet[4] = packetVersion
	packet[5] = value.flags
	binary.BigEndian.PutUint16(packet[6:8], headerSize)
	binary.BigEndian.PutUint32(packet[8:12], value.run)
	binary.BigEndian.PutUint32(packet[12:16], value.flow)
	binary.BigEndian.PutUint64(packet[16:24], value.sequence)
	binary.BigEndian.PutUint64(packet[24:32], uint64(value.sentNS))
	for index := headerSize; index < len(packet); index++ {
		packet[index] = byte(value.sequence*0x9e3779b97f4a7c15 + uint64(index))
	}
	binary.BigEndian.PutUint32(packet[32:36], crc32.ChecksumIEEE(packet[headerSize:]))
	binary.BigEndian.PutUint32(packet[36:40], crc32.ChecksumIEEE(packet[:36]))
}

func parse(packet []byte) (header, bool) {
	if len(packet) < headerSize || binary.BigEndian.Uint32(packet[0:4]) != packetMagic || packet[4] != packetVersion || binary.BigEndian.Uint16(packet[6:8]) != headerSize {
		return header{}, false
	}
	if crc32.ChecksumIEEE(packet[:36]) != binary.BigEndian.Uint32(packet[36:40]) || crc32.ChecksumIEEE(packet[headerSize:]) != binary.BigEndian.Uint32(packet[32:36]) {
		return header{}, false
	}
	return header{
		flags: packet[5], run: binary.BigEndian.Uint32(packet[8:12]), flow: binary.BigEndian.Uint32(packet[12:16]),
		sequence: binary.BigEndian.Uint64(packet[16:24]), sentNS: int64(binary.BigEndian.Uint64(packet[24:32])), checksum: binary.BigEndian.Uint32(packet[32:36]),
	}, true
}

func deadlineContext(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	if duration > 0 {
		return context.WithTimeout(parent, duration)
	}
	return context.WithCancel(parent)
}

func perWorkerRequests(total, workers, worker int) int {
	if total == 0 {
		return 0
	}
	base := total / workers
	if worker < total%workers {
		base++
	}
	return base
}
