package policyd

import (
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
		go proxyExplicitRequest(conn, upstreamAddr)
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
	header, err := readProxyHeader(downstream, explicitProxyHeaderLimit)
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

	copyDone := make(chan struct{}, 2)
	go proxyStream(upstream, downstream, copyDone)
	go proxyStream(downstream, upstream, copyDone)
	<-copyDone
}

func proxyStream(dst net.Conn, src net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	done <- struct{}{}
}

func readProxyHeader(conn net.Conn, limit int) ([]byte, error) {
	if conn == nil {
		return nil, errors.New("proxy connection is required")
	}
	if limit <= 0 {
		return nil, errors.New("proxy header limit must be positive")
	}

	header := make([]byte, 0, 1024)
	needle := []byte("\r\n\r\n")
	single := make([]byte, 1)
	for len(header) < limit {
		n, err := conn.Read(single)
		if n > 0 {
			header = append(header, single[:n]...)
			if len(header) >= len(needle) && bytes.Equal(header[len(header)-len(needle):], needle) {
				return header, nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(header) > 0 {
				break
			}
			return nil, err
		}
	}
	return nil, errors.New("proxy header incomplete or exceeds limit")
}

func rewriteWebSocketProxyHeader(header []byte) ([]byte, bool) {
	if len(header) == 0 || !hasWebSocketUpgrade(header) {
		return header, false
	}

	lineEnd := bytes.Index(header, []byte("\r\n"))
	if lineEnd <= 0 {
		return header, false
	}

	requestLine := string(header[:lineEnd])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) != 3 {
		return header, false
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
		return header, false
	}

	rewritten := append([]byte(strings.Join(parts, " ")), injectOriginalTargetHeaders(header[lineEnd:], originalTarget, originalAuthority)...)
	return rewritten, true
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
		injected.WriteString("\r\nX-Box-Original-Target: ")
		injected.WriteString(originalTarget)
	}
	if strings.TrimSpace(originalAuthority) != "" {
		injected.WriteString("\r\nX-Box-Original-Authority: ")
		injected.WriteString(originalAuthority)
	}
	injected.Write(rest[headerEnd:])
	return injected.Bytes()
}
