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
	frameVersion = 4
	headerSize   = 24
	opEcho       = 1
	opUpload     = 2
	opDownload   = 3
	opShort      = 4
	opUploadData = 5
	opUploadDone = 6
	flagResponse = 1
	flagProof    = 2

	// Bound application data accepted by the sender but not yet consumed by the
	// benchmark server. This keeps the duration-limited upload's final drain
	// below the operation timeout without turning every block into an RTT.
	uploadAckWindowBytes = 1 << 20
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
	OnError    func(error)
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
			if serveErr := s.serveConnection(connection); serveErr != nil && s.OnError != nil {
				s.OnError(serveErr)
			}
		}()
	}
}

func (s Server) serveConnection(connection net.Conn) error {
	reader := bufio.NewReaderSize(connection, 256<<10)
	writer := bufio.NewWriterSize(connection, 256<<10)
	headerBuffer := make([]byte, headerSize)
	header, err := readHeader(reader, headerBuffer)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if header.length > uint32(s.MaxPayload) {
		return fmt.Errorf("payload %d exceeds server maximum %d", header.length, s.MaxPayload)
	}
	switch header.operation {
	case opUpload:
		return s.serveUpload(reader, writer, header, headerBuffer)
	case opDownload:
		return s.serveDownload(connection, header, headerBuffer)
	case opEcho, opShort:
		payload := make([]byte, header.length)
		for {
			if _, err = io.ReadFull(reader, payload); err != nil {
				return err
			}
			if crc32.ChecksumIEEE(payload) != header.checksum {
				return errors.New("request checksum mismatch")
			}
			response := header
			response.flags |= flagResponse
			writeHeader(headerBuffer, response)
			if _, err = writer.Write(headerBuffer); err != nil {
				return err
			}
			if header.flags&flagProof != 0 {
				observed, encodeErr := protocol.EncodeEndpoint(connection.RemoteAddr())
				if encodeErr != nil {
					return encodeErr
				}
				if _, err = writer.Write(observed); err != nil {
					return err
				}
			}
			if _, err = writer.Write(payload); err != nil {
				return err
			}
			if err = writer.Flush(); err != nil {
				return err
			}
			if header.operation == opShort {
				return nil
			}
			header, err = readHeader(reader, headerBuffer)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			if header.operation != opEcho || header.length > uint32(s.MaxPayload) {
				return errors.New("unexpected frame on echo connection")
			}
			if int(header.length) != len(payload) {
				payload = make([]byte, header.length)
			}
		}
	default:
		return fmt.Errorf("unsupported TCP operation %d", header.operation)
	}
}

// An upload control header describes one repeated, checksum-protected payload
// block. sequence is the requested block count, or zero for a duration-limited
// stream. Every complete block and the end of the stream have explicit frames,
// so the benchmark does not depend on half-close propagation through a proxy.
// Progress acknowledgements bound queued data; the final acknowledgement
// proves how many complete blocks arrived.
func (s Server) serveUpload(reader io.Reader, writer *bufio.Writer, control frameHeader, headerBuffer []byte) error {
	payload := make([]byte, control.length)
	ackInterval := uploadAckInterval(len(payload))
	var completed uint64
	for {
		frame, err := readHeader(reader, headerBuffer)
		if err != nil {
			return err
		}
		if frame.operation == opUploadDone {
			if frame.flags != 0 || frame.length != 0 || frame.sequence != completed {
				return errors.New("upload finish frame mismatch")
			}
			if control.sequence != 0 && completed != control.sequence {
				return fmt.Errorf("upload finished after %d of %d blocks", completed, control.sequence)
			}
			return writeUploadAcknowledgement(writer, headerBuffer, completed)
		}
		if frame.operation != opUploadData || frame.flags != 0 || frame.length != control.length || frame.sequence != completed+1 || frame.checksum != control.checksum {
			return errors.New("upload data frame mismatch")
		}
		if control.sequence != 0 && frame.sequence > control.sequence {
			return errors.New("upload exceeded requested block count")
		}
		if _, err = io.ReadFull(reader, payload); err != nil {
			return err
		}
		if crc32.ChecksumIEEE(payload) != frame.checksum {
			return errors.New("upload payload checksum mismatch")
		}
		completed++
		if completed%ackInterval == 0 {
			if err := writeUploadAcknowledgement(writer, headerBuffer, completed); err != nil {
				return err
			}
		}
	}
}

func writeUploadAcknowledgement(writer *bufio.Writer, headerBuffer []byte, completed uint64) error {
	writeHeader(headerBuffer, frameHeader{operation: opUpload, flags: flagResponse, sequence: completed})
	if _, err := writer.Write(headerBuffer); err != nil {
		return err
	}
	return writer.Flush()
}

func uploadAckInterval(payloadBytes int) uint64 {
	if payloadBytes <= 0 || payloadBytes >= uploadAckWindowBytes {
		return 1
	}
	return uint64(uploadAckWindowBytes / payloadBytes)
}

// A download control header requests repeated checksum-protected blocks.
// sequence is the requested block count, or zero until the client closes the
// connection at its duration boundary. Frames are written continuously without
// request/response pacing between blocks.
func (s Server) serveDownload(connection net.Conn, control frameHeader, headerBuffer []byte) error {
	payload := make([]byte, control.length)
	fillPayload(payload, control.checksumSeed())
	checksum := crc32.ChecksumIEEE(payload)
	var completed uint64
	for control.sequence == 0 || completed < control.sequence {
		completed++
		response := frameHeader{operation: opDownload, flags: flagResponse, length: uint32(len(payload)), sequence: completed, checksum: checksum}
		writeHeader(headerBuffer, response)
		buffers := net.Buffers{headerBuffer, payload}
		if _, err := buffers.WriteTo(connection); err != nil {
			if control.sequence == 0 && (errors.Is(err, net.ErrClosed) || isNetworkTimeout(err)) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (h frameHeader) checksumSeed() uint64 { return uint64(h.checksum)<<32 | uint64(h.length) }

type ClientConfig struct {
	Target       string
	Mode         protocol.WorkloadMode
	PayloadBytes int
	Requests     int
	Duration     time.Duration
	Connections  int
	Timeout      time.Duration
	CollectProof bool
}

func Run(ctx context.Context, config ClientConfig) (protocol.Counters, []int64, error) {
	result, err := RunDetailed(ctx, config)
	return result.Counters, result.LatencyNS, err
}

func RunDetailed(ctx context.Context, config ClientConfig) (protocol.WorkloadResult, error) {
	startedAt := time.Now()
	if config.Connections < 1 {
		config.Connections = 1
	}
	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Second
	}
	var counters atomicCounters
	latencyByWorker := make([][]int64, config.Connections)
	pathsByWorker := make([][]protocol.SocketPathEvidence, config.Connections)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < config.Connections; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			<-start
			var err error
			switch config.Mode {
			case protocol.ModeShort:
				err = runShort(ctx, config, worker, &counters, &latencyByWorker[worker], &pathsByWorker[worker])
			case protocol.ModeBulkUpload:
				err = runUpload(ctx, config, worker, &counters)
			case protocol.ModeBulkDownload:
				err = runDownload(ctx, config, worker, &counters)
			default:
				err = runEcho(ctx, config, worker, &counters, &latencyByWorker[worker], &pathsByWorker[worker])
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
	var paths []protocol.SocketPathEvidence
	for _, workerPaths := range pathsByWorker {
		paths = append(paths, workerPaths...)
	}
	finishedAt := time.Now()
	return protocol.WorkloadResult{
		Counters: counters.snapshot(), LatencyNS: latencies, SocketPaths: paths,
		Timing: protocol.WorkloadTiming{StartedAt: startedAt, ActiveDurationNS: finishedAt.Sub(startedAt).Nanoseconds(), FinishedAt: finishedAt},
	}, counters.err()
}

// RunIdle establishes the requested number of TCP connections concurrently,
// holds them for the measurement duration, and returns them still open. The
// worker closes them only after the controller samples both processes, so RSS,
// FD and socket counts describe the resident state rather than post-cleanup.
func RunIdle(ctx context.Context, config ClientConfig) (protocol.WorkloadResult, []net.Conn, error) {
	startedAt := time.Now()
	if config.Connections < 1 || config.Duration <= 0 {
		return protocol.WorkloadResult{}, nil, errors.New("idle mode requires positive connections and duration")
	}
	connections := make([]net.Conn, config.Connections)
	errorsByConnection := make([]error, config.Connections)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for index := range connections {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			connections[index], errorsByConnection[index] = (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "tcp", config.Target)
		}(index)
	}
	close(start)
	workers.Wait()
	var failed uint64
	for _, err := range errorsByConnection {
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			closeConnections(connections)
			return protocol.WorkloadResult{}, nil, ctx.Err()
		}
		if !isTransportError(err) {
			closeConnections(connections)
			return protocol.WorkloadResult{}, nil, err
		}
		failed++
	}
	setupFinishedAt := time.Now()
	timer := time.NewTimer(config.Duration)
	select {
	case <-timer.C:
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		closeConnections(connections)
		return protocol.WorkloadResult{}, nil, ctx.Err()
	}
	finishedAt := time.Now()
	return protocol.WorkloadResult{
		Counters: protocol.Counters{Operations: uint64(len(connections)) - failed, Failed: failed},
		Timing: protocol.WorkloadTiming{
			StartedAt: startedAt, SetupDurationNS: setupFinishedAt.Sub(startedAt).Nanoseconds(),
			ActiveDurationNS: finishedAt.Sub(setupFinishedAt).Nanoseconds(), FinishedAt: finishedAt,
		},
	}, connections, nil
}

func closeConnections(connections []net.Conn) {
	for _, connection := range connections {
		if connection != nil {
			_ = connection.Close()
		}
	}
}

type atomicCounters struct {
	operations    atomic.Uint64
	failed        atomic.Uint64
	corrupt       atomic.Uint64
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
	return protocol.Counters{
		Operations: c.operations.Load(), Failed: c.failed.Load(), Corrupt: c.corrupt.Load(),
		BytesSent: c.bytesSent.Load(), BytesReceived: c.bytesReceived.Load(),
	}
}

func runEcho(ctx context.Context, config ClientConfig, worker int, counters *atomicCounters, latencies *[]int64, paths *[]protocol.SocketPathEvidence) error {
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
	end := endTime(config.Duration)
	for completed := 0; requests == 0 || completed < requests; completed++ {
		if ctx.Err() != nil || (!end.IsZero() && time.Now().After(end)) {
			return nil
		}
		sequence++
		fillPayload(payload, sequence)
		operation := uint8(opEcho)
		if config.Mode == protocol.ModeShort {
			operation = opShort
		}
		header := frameHeader{operation: operation, length: uint32(len(payload)), sequence: sequence, checksum: crc32.ChecksumIEEE(payload)}
		if config.CollectProof && completed == 0 {
			header.flags |= flagProof
		}
		started := time.Now()
		if err = connection.SetDeadline(operationDeadline(started, end, config.Timeout)); err != nil {
			return err
		}
		writeHeader(headerBuffer, header)
		if err = writeAll(connection, headerBuffer); err != nil {
			return err
		}
		if err = writeAll(connection, payload); err != nil {
			return err
		}
		counters.bytesSent.Add(uint64(len(payload)))
		response, err := readHeader(connection, headerBuffer)
		if err != nil {
			return err
		}
		expectedFlags := uint16(flagResponse)
		if header.flags&flagProof != 0 {
			expectedFlags |= flagProof
		}
		if response.flags != expectedFlags || response.sequence != sequence || response.operation != operation || response.length != uint32(len(responsePayload)) {
			return errors.New("response header mismatch")
		}
		if header.flags&flagProof != 0 {
			observed := make([]byte, protocol.EncodedEndpointSize)
			if _, err = io.ReadFull(connection, observed); err != nil {
				return err
			}
			serverPeer, decodeErr := protocol.DecodeEndpoint(observed)
			if decodeErr != nil {
				return decodeErr
			}
			clientLocal, canonicalErr := protocol.CanonicalEndpoint(connection.LocalAddr().String())
			if canonicalErr != nil {
				return canonicalErr
			}
			*paths = append(*paths, protocol.SocketPathEvidence{Network: "tcp", ClientLocal: clientLocal, ServerObservedPeer: serverPeer})
		}
		if _, err = io.ReadFull(connection, responsePayload); err != nil {
			return err
		}
		counters.bytesReceived.Add(uint64(len(responsePayload)))
		if crc32.ChecksumIEEE(responsePayload) != response.checksum {
			return errors.New("response checksum mismatch")
		}
		*latencies = append(*latencies, time.Since(started).Nanoseconds())
		counters.operations.Add(1)
	}
	return nil
}

func runShort(ctx context.Context, config ClientConfig, worker int, counters *atomicCounters, latencies *[]int64, paths *[]protocol.SocketPathEvidence) error {
	requests := perWorkerRequests(config.Requests, config.Connections, worker)
	end := endTime(config.Duration)
	for completed := 0; requests == 0 || completed < requests; completed++ {
		if ctx.Err() != nil || (!end.IsZero() && time.Now().After(end)) {
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
		var localPaths []protocol.SocketPathEvidence
		err := runEcho(ctx, one, worker+completed, localCounters, &localLatency, &localPaths)
		counters.operations.Add(localCounters.operations.Load())
		counters.bytesSent.Add(localCounters.bytesSent.Load())
		counters.bytesReceived.Add(localCounters.bytesReceived.Load())
		*paths = append(*paths, localPaths...)
		if err == nil {
			*latencies = append(*latencies, time.Since(started).Nanoseconds())
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isTransportError(err) {
			counters.failed.Add(1)
			continue
		}
		counters.corrupt.Add(1)
		return err
	}
	return nil
}

func isTransportError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func runUpload(ctx context.Context, config ClientConfig, worker int, counters *atomicCounters) error {
	connection, err := dialTCP(ctx, config)
	if err != nil {
		return err
	}
	defer connection.Close()
	payload := make([]byte, config.PayloadBytes)
	fillPayload(payload, uint64(worker+1))
	blocks := perWorkerRequests(config.Requests, config.Connections, worker)
	control := frameHeader{operation: opUpload, length: uint32(len(payload)), sequence: uint64(blocks), checksum: crc32.ChecksumIEEE(payload)}
	headerBuffer := make([]byte, headerSize)
	writeHeader(headerBuffer, control)
	if err = writeAll(connection, headerBuffer); err != nil {
		return err
	}
	end := endTime(config.Duration)
	ackInterval := uploadAckInterval(len(payload))
	var completed uint64
	for blocks == 0 || completed < uint64(blocks) {
		if ctx.Err() != nil || (!end.IsZero() && time.Now().After(end)) {
			break
		}
		writeDeadline := time.Now().Add(config.Timeout)
		_ = connection.SetWriteDeadline(writeDeadline)
		data := frameHeader{operation: opUploadData, length: uint32(len(payload)), sequence: completed + 1, checksum: control.checksum}
		writeHeader(headerBuffer, data)
		buffers := net.Buffers{headerBuffer, payload}
		if _, err = buffers.WriteTo(connection); err != nil {
			return err
		}
		completed++
		counters.operations.Add(1)
		counters.bytesSent.Add(uint64(len(payload)))
		if completed%ackInterval == 0 {
			if err = readUploadAcknowledgement(connection, headerBuffer, completed, config.Timeout); err != nil {
				return err
			}
		}
	}
	if err = connection.SetWriteDeadline(time.Now().Add(config.Timeout)); err != nil {
		return err
	}
	writeHeader(headerBuffer, frameHeader{operation: opUploadDone, sequence: completed})
	if err = writeAll(connection, headerBuffer); err != nil {
		return err
	}
	if err = readUploadAcknowledgement(connection, headerBuffer, completed, config.Timeout); err != nil {
		return err
	}
	return nil
}

func readUploadAcknowledgement(connection net.Conn, headerBuffer []byte, completed uint64, timeout time.Duration) error {
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	response, err := readHeader(connection, headerBuffer)
	if err != nil {
		return err
	}
	if response.operation != opUpload || response.flags != flagResponse || response.sequence != completed {
		return fmt.Errorf("upload acknowledgement mismatch: completed=%d acknowledged=%d", completed, response.sequence)
	}
	return nil
}

func runDownload(ctx context.Context, config ClientConfig, worker int, counters *atomicCounters) error {
	connection, err := dialTCP(ctx, config)
	if err != nil {
		return err
	}
	defer connection.Close()
	blocks := perWorkerRequests(config.Requests, config.Connections, worker)
	control := frameHeader{operation: opDownload, length: uint32(config.PayloadBytes), sequence: uint64(blocks), checksum: uint32(worker + 1)}
	headerBuffer := make([]byte, headerSize)
	writeHeader(headerBuffer, control)
	if err = writeAll(connection, headerBuffer); err != nil {
		return err
	}
	expectedPayload := make([]byte, config.PayloadBytes)
	fillPayload(expectedPayload, control.checksumSeed())
	expectedChecksum := crc32.ChecksumIEEE(expectedPayload)
	payload := make([]byte, config.PayloadBytes)
	end := endTime(config.Duration)
	var completed uint64
	for blocks == 0 || completed < uint64(blocks) {
		if ctx.Err() != nil || (!end.IsZero() && time.Now().After(end)) {
			return nil
		}
		deadline := time.Now().Add(config.Timeout)
		if !end.IsZero() && end.Before(deadline) {
			deadline = end
		}
		_ = connection.SetReadDeadline(deadline)
		response, readErr := readHeader(connection, headerBuffer)
		if readErr != nil {
			if blocks == 0 && isNetworkTimeout(readErr) {
				return nil
			}
			return readErr
		}
		if response.operation != opDownload || response.flags != flagResponse || response.length != uint32(len(payload)) || response.sequence != completed+1 || response.checksum != expectedChecksum {
			return errors.New("download frame header mismatch")
		}
		if _, err = io.ReadFull(connection, payload); err != nil {
			if blocks == 0 && isNetworkTimeout(err) {
				return nil
			}
			return err
		}
		if crc32.ChecksumIEEE(payload) != expectedChecksum {
			return errors.New("download payload checksum mismatch")
		}
		completed++
		counters.operations.Add(1)
		counters.bytesReceived.Add(uint64(len(payload)))
	}
	return nil
}

func dialTCP(ctx context.Context, config ClientConfig) (*net.TCPConn, error) {
	connection, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "tcp", config.Target)
	if err != nil {
		return nil, err
	}
	tcpConnection, ok := connection.(*net.TCPConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("TCP dial did not return a TCP connection")
	}
	return tcpConnection, nil
}

func endTime(duration time.Duration) time.Time {
	if duration <= 0 {
		return time.Time{}
	}
	return time.Now().Add(duration)
}

func operationDeadline(started, end time.Time, timeout time.Duration) time.Time {
	deadline := started.Add(timeout)
	if !end.IsZero() && end.Before(deadline) {
		return end
	}
	return deadline
}

func isNetworkTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
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
		operation: buffer[5], flags: binary.BigEndian.Uint16(buffer[6:8]), length: binary.BigEndian.Uint32(buffer[8:12]),
		sequence: binary.BigEndian.Uint64(buffer[12:20]), checksum: binary.BigEndian.Uint32(buffer[20:24]),
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
