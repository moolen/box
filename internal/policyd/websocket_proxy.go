package policyd

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	neturl "net/url"
	"strings"
	"time"
)

const (
	explicitProxyHeaderLimit   = 64 * 1024
	explicitProxyHeaderTimeout = 10 * time.Second
	explicitProxyStreamTimeout = 2 * time.Minute
	explicitProxyMaxConcurrent = 128
	explicitProxyReadBuffer    = 4096
)

func (s *Server) serveExplicitProxy(upstreamAddr string) {
	if s == nil || s.proxyListener == nil || strings.TrimSpace(upstreamAddr) == "" {
		return
	}
	for {
		conn, err := s.proxyListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			_ = s.Stop()
			return
		}
		if !s.tryAcquireProxySlot() {
			_ = conn.Close()
			continue
		}
		go func() {
			defer s.releaseProxySlot()
			proxyExplicitRequest(conn, upstreamAddr)
		}()
	}
}

func (s *Server) tryAcquireProxySlot() bool {
	if s == nil || s.proxySlots == nil {
		return true
	}
	select {
	case s.proxySlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseProxySlot() {
	if s == nil || s.proxySlots == nil {
		return
	}
	select {
	case <-s.proxySlots:
	default:
	}
}

func proxyExplicitRequest(downstream net.Conn, upstreamAddr string) {
	if downstream == nil {
		return
	}
	defer downstream.Close()

	if err := downstream.SetReadDeadline(time.Now().Add(explicitProxyHeaderTimeout)); err != nil {
		return
	}
	reader := bufio.NewReaderSize(downstream, explicitProxyReadBuffer)
	header, err := readProxyHeader(reader, explicitProxyHeaderLimit)
	if err != nil {
		return
	}
	_ = downstream.SetReadDeadline(time.Time{})

	header, _ = rewriteWebSocketProxyHeader(header)

	upstream, err := net.Dial("tcp", strings.TrimSpace(upstreamAddr))
	if err != nil {
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(header); err != nil {
		return
	}

	bufferedDownstream := &bufferedConn{
		Conn:   downstream,
		reader: reader,
	}
	copyDone := make(chan struct{}, 2)
	go proxyStream(upstream, bufferedDownstream, copyDone)
	go proxyStream(bufferedDownstream, upstream, copyDone)
	<-copyDone
}

func proxyStream(dst net.Conn, src net.Conn, done chan<- struct{}) {
	buf := make([]byte, 32*1024)
	for {
		if err := src.SetReadDeadline(time.Now().Add(explicitProxyStreamTimeout)); err != nil {
			break
		}
		n, err := src.Read(buf)
		if n > 0 {
			if setErr := dst.SetWriteDeadline(time.Now().Add(explicitProxyStreamTimeout)); setErr != nil {
				break
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	done <- struct{}{}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c == nil || c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}

func readProxyHeader(reader *bufio.Reader, limit int) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("proxy reader is required")
	}
	if limit <= 0 {
		return nil, errors.New("proxy header limit must be positive")
	}

	header := make([]byte, 0, 1024)
	needle := []byte("\r\n\r\n")
	for len(header) < limit {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			if len(header)+len(chunk) > limit {
				return nil, errors.New("proxy header incomplete or exceeds limit")
			}
			header = append(header, chunk...)
			if len(header) >= len(needle) && bytes.Contains(header, needle) {
				return header, nil
			}
		}
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if errors.Is(err, io.EOF) && len(header) > 0 {
				break
			}
			return nil, err
		}
	}
	return nil, errors.New("proxy header incomplete or exceeds limit")
}

func rewriteWebSocketProxyHeader(header []byte) ([]byte, bool) {
	sanitized := stripInternalProxyHeaders(header)
	if len(sanitized) == 0 || !hasWebSocketUpgrade(sanitized) {
		return sanitized, false
	}

	lineEnd := bytes.Index(sanitized, []byte("\r\n"))
	if lineEnd <= 0 {
		return sanitized, false
	}

	requestLine := string(sanitized[:lineEnd])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) != 3 {
		return sanitized, false
	}

	target := parts[1]
	originalTarget := target
	originalAuthority := authorityFromAbsoluteTarget(target)
	switch {
	case strings.HasPrefix(strings.ToLower(target), "ws://"):
		parts[1] = "http://" + target[len("ws://"):]
	case strings.HasPrefix(strings.ToLower(target), "wss://"):
		parts[1] = "https://" + target[len("wss://"):]
	default:
		return sanitized, false
	}

	rewritten := append([]byte(strings.Join(parts, " ")), injectOriginalTargetHeaders(sanitized[lineEnd:], originalTarget, originalAuthority)...)
	return rewritten, true
}

func stripInternalProxyHeaders(header []byte) []byte {
	if len(header) == 0 {
		return header
	}

	lineEnd := bytes.Index(header, []byte("\r\n"))
	if lineEnd <= 0 {
		return header
	}
	rest := header[lineEnd+2:]
	headerEnd := bytes.Index(rest, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return header
	}

	lines := bytes.Split(rest[:headerEnd], []byte("\r\n"))
	var sanitized bytes.Buffer
	sanitized.Write(header[:lineEnd])
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		nameEnd := bytes.IndexByte(line, ':')
		if nameEnd <= 0 {
			sanitized.WriteString("\r\n")
			sanitized.Write(line)
			continue
		}
		if isInternalProxyHeader(string(line[:nameEnd])) {
			continue
		}
		sanitized.WriteString("\r\n")
		sanitized.Write(line)
	}
	sanitized.Write(rest[headerEnd:])
	return sanitized.Bytes()
}

func isInternalProxyHeader(name string) bool {
	trimmed := strings.TrimSpace(name)
	return strings.EqualFold(trimmed, headerOriginalTarget) ||
		strings.EqualFold(trimmed, headerOriginalAuthority) ||
		strings.EqualFold(trimmed, headerTrustedMetadata)
}

func hasWebSocketUpgrade(header []byte) bool {
	lines := bytes.Split(header, []byte("\r\n"))
	for _, rawLine := range lines[1:] {
		line := strings.TrimSpace(string(rawLine))
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(name), "Upgrade") {
			continue
		}
		return strings.EqualFold(strings.TrimSpace(value), "websocket")
	}
	return false
}

func authorityFromAbsoluteTarget(target string) string {
	if strings.TrimSpace(target) == "" {
		return ""
	}
	parsed, err := neturl.Parse(strings.TrimSpace(target))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Host)
}

func injectOriginalTargetHeaders(rest []byte, originalTarget string, originalAuthority string) []byte {
	if len(rest) == 0 {
		return rest
	}

	headerEnd := bytes.Index(rest, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return rest
	}

	var injected bytes.Buffer
	injected.Write(rest[:headerEnd])
	if strings.TrimSpace(originalTarget) != "" {
		injected.WriteString("\r\n")
		injected.WriteString(headerOriginalTarget)
		injected.WriteString(": ")
		injected.WriteString(originalTarget)
	}
	if strings.TrimSpace(originalAuthority) != "" {
		injected.WriteString("\r\n")
		injected.WriteString(headerOriginalAuthority)
		injected.WriteString(": ")
		injected.WriteString(originalAuthority)
	}
	injected.WriteString("\r\n")
	injected.WriteString(headerTrustedMetadata)
	injected.WriteString(": ")
	injected.WriteString(trustedExplicitWebsocket)
	injected.Write(rest[headerEnd:])
	return injected.Bytes()
}
