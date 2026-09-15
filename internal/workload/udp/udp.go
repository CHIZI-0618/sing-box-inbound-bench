package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

const (
	packetMagic   = 0x53424955 // SBIU
	packetVersion = 1
	headerSize    = 40
	flagResponse  = 1
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
	Timeout      time.Duration
	RunHash      uint32
}

func Run(ctx context.Context, config ClientConfig) (protocol.Counters, []int64, error) {
	if config.Flows < 1 {
		config.Flows = 1
	}
	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Second
	}
	if config.Mode == "" {
		config.Mode = protocol.ModeEcho
	}
	workDuration := config.Duration
	if config.Mode == protocol.ModePPS {
		workDuration = 0
	}
	ctx, cancel := deadlineContext(ctx, workDuration)
	defer cancel()
	var counters atomicCounters
	latencyByFlow := make([][]int64, config.Flows)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for flow := 0; flow < config.Flows; flow++ {
		workers.Add(1)
		go func(flow int) {
			defer workers.Done()
			<-start
			var err error
			if config.Mode == protocol.ModePPS {
				err = runPPSFlow(ctx, config, flow, &counters, &latencyByFlow[flow])
			} else {
				err = runEchoFlow(ctx, config, flow, &counters, &latencyByFlow[flow])
			}
			if err != nil && ctx.Err() == nil {
				counters.setError(err)
			}
		}(flow)
	}
	close(start)
	workers.Wait()
	latencies := make([]int64, 0)
	for _, values := range latencyByFlow {
		latencies = append(latencies, values...)
	}
	return counters.snapshot(), latencies, counters.err()
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

func runEchoFlow(ctx context.Context, config ClientConfig, flow int, counters *atomicCounters, latencies *[]int64) error {
	connection, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "udp", config.Target)
	if err != nil {
		return err
	}
	defer connection.Close()
	packet := make([]byte, headerSize+config.PayloadBytes)
	response := make([]byte, len(packet))
	requests := perWorkerRequests(config.Requests, config.Flows, flow)
	var interval time.Duration
	if config.OfferedPPS > 0 {
		perFlowPPS := (config.OfferedPPS + config.Flows - 1) / config.Flows
		interval = time.Second / time.Duration(perFlowPPS)
	}
	nextSend := time.Now()
	var previous uint64
	for completed := 0; requests == 0 || completed < requests; completed++ {
		if ctx.Err() != nil {
			return nil
		}
		if interval > 0 {
			if delay := time.Until(nextSend); delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return nil
				}
			}
			nextSend = nextSend.Add(interval)
		}
		sequence := uint64(completed + 1)
		sentAt := time.Now()
		build(packet, header{run: config.RunHash, flow: uint32(flow), sequence: sequence, sentNS: sentAt.UnixNano()})
		if err = connection.SetDeadline(sentAt.Add(config.Timeout)); err != nil {
			return err
		}
		if _, err = connection.Write(packet); err != nil {
			return err
		}
		counters.packetsSent.Add(1)
		counters.bytesSent.Add(uint64(len(packet)))
		length, readErr := connection.Read(response)
		if readErr != nil {
			if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				counters.lost.Add(1)
				continue
			}
			return readErr
		}
		counters.packetsReceived.Add(1)
		counters.bytesReceived.Add(uint64(length))
		got, valid := parse(response[:length])
		if !valid || got.flags&flagResponse == 0 || got.run != config.RunHash || got.flow != uint32(flow) {
			counters.corrupt.Add(1)
			continue
		}
		if got.sequence <= previous {
			counters.reordered.Add(1)
		}
		previous = got.sequence
		if got.sequence != sequence {
			counters.reordered.Add(1)
			continue
		}
		*latencies = append(*latencies, time.Since(sentAt).Nanoseconds())
		counters.operations.Add(1)
	}
	return nil
}

func runPPSFlow(ctx context.Context, config ClientConfig, flow int, counters *atomicCounters, latencies *[]int64) error {
	connection, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "udp", config.Target)
	if err != nil {
		return err
	}
	defer connection.Close()
	perFlowPPS := (config.OfferedPPS + config.Flows - 1) / config.Flows
	if perFlowPPS < 1 {
		return errors.New("offered PPS must be positive")
	}
	requests := perWorkerRequests(config.Requests, config.Flows, flow)
	if requests == 0 {
		requests = int((config.Duration*time.Duration(perFlowPPS) + time.Second - 1) / time.Second)
	}
	if requests < 1 {
		return errors.New("PPS mode requires requests or duration")
	}
	interval := time.Second / time.Duration(perFlowPPS)
	packet := make([]byte, headerSize+config.PayloadBytes)
	response := make([]byte, len(packet))
	sentAt := make([]atomic.Int64, requests+1)
	seen := make([]bool, requests+1)
	clockBase := time.Now()
	senderDone := make(chan struct{})
	receiverDone := make(chan error, 1)
	deadline := time.Now().Add(time.Duration(requests)*interval + config.Timeout)
	if err = connection.SetReadDeadline(deadline); err != nil {
		return err
	}
	go func() {
		var previous uint64
		var received int
		for {
			length, readErr := connection.Read(response)
			if readErr != nil {
				if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
					receiverDone <- nil
					return
				}
				receiverDone <- readErr
				return
			}
			counters.packetsReceived.Add(1)
			counters.bytesReceived.Add(uint64(length))
			got, valid := parse(response[:length])
			if !valid || got.flags&flagResponse == 0 || got.run != config.RunHash || got.flow != uint32(flow) || got.sequence == 0 || got.sequence > uint64(requests) {
				counters.corrupt.Add(1)
				continue
			}
			if got.sequence <= previous {
				counters.reordered.Add(1)
			}
			previous = got.sequence
			if seen[got.sequence] {
				counters.reordered.Add(1)
				continue
			}
			seen[got.sequence] = true
			startedOffset := sentAt[got.sequence].Load()
			if startedOffset == 0 {
				counters.corrupt.Add(1)
				continue
			}
			*latencies = append(*latencies, time.Since(clockBase).Nanoseconds()-(startedOffset-1))
			counters.operations.Add(1)
			received++
			select {
			case <-senderDone:
				if received >= requests {
					receiverDone <- nil
					return
				}
			default:
			}
		}
	}()
	nextSend := time.Now()
	for sequence := 1; sequence <= requests; sequence++ {
		if delay := time.Until(nextSend); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				close(senderDone)
				_ = connection.SetReadDeadline(time.Now())
				<-receiverDone
				return nil
			}
		}
		now := time.Now()
		sentAt[sequence].Store(time.Since(clockBase).Nanoseconds() + 1)
		build(packet, header{run: config.RunHash, flow: uint32(flow), sequence: uint64(sequence), sentNS: now.UnixNano()})
		if _, err = connection.Write(packet); err != nil {
			close(senderDone)
			_ = connection.SetReadDeadline(time.Now())
			<-receiverDone
			return err
		}
		counters.packetsSent.Add(1)
		counters.bytesSent.Add(uint64(len(packet)))
		nextSend = nextSend.Add(interval)
	}
	close(senderDone)
	err = <-receiverDone
	// Each flow shares the aggregate counter. Count loss per flow using its
	// own latency count, which contains exactly one entry per valid response.
	counters.lost.Add(uint64(requests - len(*latencies)))
	return err
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
