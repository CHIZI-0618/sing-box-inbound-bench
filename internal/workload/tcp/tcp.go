package tcp

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CHIZI-0618/sing-box-inbound-bench/internal/protocol"
)

const (
	frameMagic   = 0x53424942 // SBIB
	frameVersion = 1
	headerSize   = 24
	opEcho       = 1
	opUpload     = 2
	opDownload   = 3
	opShort      = 4
	flagResponse = 1
)

type frameHeader struct {
	operation uint8
	flags     uint16
	length    uint32
	sequence  uint64
	checksum  uint32
}

type Server struct {
	MaxPayload int
}

func (s Server) Serve(ctx context.Context, listener net.Listener) error {
	if s.MaxPayload == 0 {
		s.MaxPayload = 1 << 20
	}
	var connections sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	defer connections.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer connection.Close()
			_ = s.serveConnection(connection)
		}()
	}
}

func (s Server) serveConnection(connection net.Conn) error {
	reader := bufio.NewReaderSize(connection, 64<<10)
	writer := bufio.NewWriterSize(connection, 64<<10)
	headerBuffer := make([]byte, headerSize)
	payload := make([]byte, s.MaxPayload)
	for {
		header, err := readHeader(reader, headerBuffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if header.length > uint32(len(payload)) {
			return fmt.Errorf("payload %d exceeds server maximum %d", header.length, len(payload))
		}
		body := payload[:header.length]
		switch header.operation {
		case opEcho, opUpload, opShort:
			if _, err = io.ReadFull(reader, body); err != nil {
				return err
			}
			if crc32.ChecksumIEEE(body) != header.checksum {
				return errors.New("request checksum mismatch")
			}
			response := header
			response.flags = flagResponse
			if header.operation == opUpload {
				response.length = 0
				response.checksum = 0
			}
			writeHeader(headerBuffer, response)
			if _, err = writer.Write(headerBuffer); err != nil {
				return err
			}
			if header.operation == opEcho || header.operation == opShort {
				if _, err = writer.Write(body); err != nil {
					return err
				}
			}
		case opDownload:
			fillPayload(body, header.sequence)
			response := header
			response.flags = flagResponse
			response.checksum = crc32.ChecksumIEEE(body)
			writeHeader(headerBuffer, response)
			if _, err = writer.Write(headerBuffer); err != nil {
				return err
			}
			if _, err = writer.Write(body); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported TCP operation %d", header.operation)
		}
		if err = writer.Flush(); err != nil {
			return err
		}
		if header.operation == opShort {
			return nil
		}
	}
}

type ClientConfig struct {
	Target       string
	Mode         protocol.WorkloadMode
	PayloadBytes int
	Requests     int
	Duration     time.Duration
	Connections  int
	Timeout      time.Duration
}

func Run(ctx context.Context, config ClientConfig) (protocol.Counters, []int64, error) {
	if config.Connections < 1 {
		config.Connections = 1
	}
	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Second
	}
	ctx, cancel := deadlineContext(ctx, config.Duration)
	defer cancel()
	var counters atomicCounters
	latencyByWorker := make([][]int64, config.Connections)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < config.Connections; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			<-start
			var err error
			if config.Mode == protocol.ModeShort {
				err = runShort(ctx, config, worker, &counters, &latencyByWorker[worker])
			} else {
				err = runPersistent(ctx, config, worker, &counters, &latencyByWorker[worker])
			}
			if err != nil && ctx.Err() == nil {
				counters.setError(err)
			}
		}(worker)
	}
	close(start)
	workers.Wait()
	latencies := make([]int64, 0)
	for _, workerLatency := range latencyByWorker {
		latencies = append(latencies, workerLatency...)
	}
	return counters.snapshot(), latencies, counters.err()
}

type atomicCounters struct {
	operations    atomic.Uint64
	failed        atomic.Uint64
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	once          sync.Once
	firstError    error
}

func (c *atomicCounters) setError(err error) {
	c.failed.Add(1)
	c.once.Do(func() { c.firstError = err })
}

func (c *atomicCounters) err() error { return c.firstError }

func (c *atomicCounters) snapshot() protocol.Counters {
	return protocol.Counters{Operations: c.operations.Load(), Failed: c.failed.Load(), BytesSent: c.bytesSent.Load(), BytesReceived: c.bytesReceived.Load()}
}

func runPersistent(ctx context.Context, config ClientConfig, worker int, counters *atomicCounters, latencies *[]int64) error {
	connection, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "tcp", config.Target)
	if err != nil {
		return err
	}
	defer connection.Close()
	payload := make([]byte, config.PayloadBytes)
	headerBuffer := make([]byte, headerSize)
	responsePayload := make([]byte, config.PayloadBytes)
	sequence := uint64(worker) << 48
	requests := perWorkerRequests(config.Requests, config.Connections, worker)
	for completed := 0; requests == 0 || completed < requests; completed++ {
		if err = ctx.Err(); err != nil {
			return nil
		}
		sequence++
		fillPayload(payload, sequence)
		operation := uint8(opEcho)
		switch config.Mode {
		case protocol.ModeBulkUpload:
			operation = opUpload
		case protocol.ModeBulkDownload:
			operation = opDownload
		case protocol.ModeShort:
			operation = opShort
		}
		header := frameHeader{operation: operation, length: uint32(len(payload)), sequence: sequence}
		if operation != opDownload {
			header.checksum = crc32.ChecksumIEEE(payload)
		}
		started := time.Now()
		if err = connection.SetDeadline(started.Add(config.Timeout)); err != nil {
			return err
		}
		writeHeader(headerBuffer, header)
		if err = writeAll(connection, headerBuffer); err != nil {
			return err
		}
		counters.bytesSent.Add(headerSize)
		if operation != opDownload {
			if err = writeAll(connection, payload); err != nil {
				return err
			}
			counters.bytesSent.Add(uint64(len(payload)))
		}
		response, err := readHeader(connection, headerBuffer)
		if err != nil {
			return err
		}
		counters.bytesReceived.Add(headerSize)
		if response.flags != flagResponse || response.sequence != sequence || response.operation != operation {
			return errors.New("response header mismatch")
		}
		if response.length > 0 {
			if int(response.length) > len(responsePayload) {
				return errors.New("response payload too large")
			}
			body := responsePayload[:response.length]
			if _, err = io.ReadFull(connection, body); err != nil {
				return err
			}
			counters.bytesReceived.Add(uint64(response.length))
			if crc32.ChecksumIEEE(body) != response.checksum {
				return errors.New("response checksum mismatch")
			}
		}
		*latencies = append(*latencies, time.Since(started).Nanoseconds())
		counters.operations.Add(1)
	}
	return nil
}

func runShort(ctx context.Context, config ClientConfig, worker int, counters *atomicCounters, latencies *[]int64) error {
	requests := perWorkerRequests(config.Requests, config.Connections, worker)
	for completed := 0; requests == 0 || completed < requests; completed++ {
		if ctx.Err() != nil {
			return nil
		}
		one := config
		one.Mode = protocol.ModeShort
		one.Requests = 1
		one.Duration = 0
		one.Connections = 1
		started := time.Now()
		localCounters := &atomicCounters{}
		var localLatency []int64
		if err := runPersistent(ctx, one, worker+completed, localCounters, &localLatency); err != nil {
			return err
		}
		counters.operations.Add(localCounters.operations.Load())
		counters.bytesSent.Add(localCounters.bytesSent.Load())
		counters.bytesReceived.Add(localCounters.bytesReceived.Load())
		*latencies = append(*latencies, time.Since(started).Nanoseconds())
	}
	return nil
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		content = content[written:]
	}
	return nil
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

func writeHeader(buffer []byte, header frameHeader) {
	binary.BigEndian.PutUint32(buffer[0:4], frameMagic)
	buffer[4] = frameVersion
	buffer[5] = header.operation
	binary.BigEndian.PutUint16(buffer[6:8], header.flags)
	binary.BigEndian.PutUint32(buffer[8:12], header.length)
	binary.BigEndian.PutUint64(buffer[12:20], header.sequence)
	binary.BigEndian.PutUint32(buffer[20:24], header.checksum)
}

func readHeader(reader io.Reader, buffer []byte) (frameHeader, error) {
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return frameHeader{}, err
	}
	if binary.BigEndian.Uint32(buffer[0:4]) != frameMagic || buffer[4] != frameVersion {
		return frameHeader{}, errors.New("invalid TCP benchmark frame")
	}
	return frameHeader{
		operation: buffer[5],
		flags:     binary.BigEndian.Uint16(buffer[6:8]),
		length:    binary.BigEndian.Uint32(buffer[8:12]),
		sequence:  binary.BigEndian.Uint64(buffer[12:20]),
		checksum:  binary.BigEndian.Uint32(buffer[20:24]),
	}, nil
}

func fillPayload(payload []byte, seed uint64) {
	state := seed ^ 0x9e3779b97f4a7c15
	for index := range payload {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		payload[index] = byte(state)
	}
}
