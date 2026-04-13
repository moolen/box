package policyd

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestRewriteWebSocketProxyHeaderRewritesWSAbsoluteForm(t *testing.T) {
	input := []byte("GET ws://example.com:8080/chat HTTP/1.1\r\nHost: example.com:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

	got, rewritten := rewriteWebSocketProxyHeader(input)

	if !rewritten {
		t.Fatal("rewritten = false, want true")
	}
	if !bytes.HasPrefix(got, []byte("GET http://example.com:8080/chat HTTP/1.1\r\n")) {
		t.Fatalf("header = %q, want rewritten http absolute form", got)
	}
	if !bytes.Contains(got, []byte("\r\nX-Box-Trusted-Metadata: explicit-proxy-websocket-v1\r\n")) {
		t.Fatalf("header = %q, want trusted metadata marker", got)
	}
}

func TestRewriteWebSocketProxyHeaderRewritesWSSAbsoluteForm(t *testing.T) {
	input := []byte("GET wss://example.com/chat HTTP/1.1\r\nHost: example.com\r\nupgrade: WebSocket\r\nconnection: keep-alive, Upgrade\r\n\r\n")

	got, rewritten := rewriteWebSocketProxyHeader(input)

	if !rewritten {
		t.Fatal("rewritten = false, want true")
	}
	if !bytes.HasPrefix(got, []byte("GET https://example.com/chat HTTP/1.1\r\n")) {
		t.Fatalf("header = %q, want rewritten https absolute form", got)
	}
	if !bytes.Contains(got, []byte("\r\nX-Box-Trusted-Metadata: explicit-proxy-websocket-v1\r\n")) {
		t.Fatalf("header = %q, want trusted metadata marker", got)
	}
}

func TestRewriteWebSocketProxyHeaderStripsInternalHeadersFromNonWebSocketRequests(t *testing.T) {
	input := []byte("GET http://example.com/chat HTTP/1.1\r\nHost: example.com\r\nX-Box-Original-Target: https://evil.example/\r\nX-Box-Original-Authority: evil.example:443\r\nX-Box-Trusted-Metadata: attacker\r\n\r\n")

	got, rewritten := rewriteWebSocketProxyHeader(input)

	if rewritten {
		t.Fatal("rewritten = true, want false")
	}
	if bytes.Contains(got, []byte("X-Box-Original-Target")) || bytes.Contains(got, []byte("X-Box-Original-Authority")) || bytes.Contains(got, []byte("X-Box-Trusted-Metadata")) {
		t.Fatalf("header = %q, want internal headers stripped", got)
	}
}

func TestRewriteWebSocketProxyHeaderLeavesWSRequestWithoutUpgradeUntouched(t *testing.T) {
	input := []byte("GET ws://example.com/chat HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n")

	got, rewritten := rewriteWebSocketProxyHeader(input)

	if rewritten {
		t.Fatal("rewritten = true, want false")
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("header = %q, want unchanged request", got)
	}
}

func TestRewriteWebSocketProxyHeaderReplacesAttackerSuppliedInternalHeaders(t *testing.T) {
	input := []byte("GET ws://example.com/chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Box-Original-Target: https://evil.example/\r\nX-Box-Original-Authority: evil.example:443\r\nX-Box-Trusted-Metadata: attacker\r\n\r\n")

	got, rewritten := rewriteWebSocketProxyHeader(input)

	if !rewritten {
		t.Fatal("rewritten = false, want true")
	}
	if bytes.Contains(got, []byte("attacker")) || bytes.Contains(got, []byte("evil.example")) {
		t.Fatalf("header = %q, want attacker-supplied internal headers removed", got)
	}
	if !bytes.Contains(got, []byte("\r\nX-Box-Original-Target: ws://example.com/chat\r\n")) {
		t.Fatalf("header = %q, want authoritative original target", got)
	}
	if !bytes.Contains(got, []byte("\r\nX-Box-Original-Authority: example.com\r\n")) {
		t.Fatalf("header = %q, want authoritative original authority", got)
	}
	if !bytes.Contains(got, []byte("\r\nX-Box-Trusted-Metadata: explicit-proxy-websocket-v1\r\n")) {
		t.Fatalf("header = %q, want trusted metadata marker", got)
	}
}

func TestProxyExplicitRequestRefreshesDeadlinesDuringStreaming(t *testing.T) {
	downstreamClient, downstreamServer := net.Pipe()
	defer downstreamClient.Close()

	recording := &recordingConn{
		Conn:           downstreamServer,
		readDeadlines:  make(chan time.Time, 8),
		writeDeadlines: make(chan time.Time, 8),
	}
	defer recording.Close()

	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer upstreamListener.Close()

	upstreamAccepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := upstreamListener.Accept()
		if acceptErr == nil {
			upstreamAccepted <- conn
		}
	}()

	done := make(chan struct{})
	go func() {
		proxyExplicitRequest(recording, upstreamListener.Addr().String())
		close(done)
	}()

	if _, err := downstreamClient.Write([]byte("GET http://example.com/chat HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("downstreamClient.Write() error = %v", err)
	}

	var upstreamConn net.Conn
	select {
	case upstreamConn = <-upstreamAccepted:
		defer upstreamConn.Close()
	case <-time.After(250 * time.Millisecond):
		t.Fatal("proxyExplicitRequest() did not connect upstream")
	}

	buf := make([]byte, 128)
	if _, err := upstreamConn.Read(buf); err != nil {
		t.Fatalf("upstreamConn.Read() error = %v", err)
	}

	var deadlines []time.Time
	deadlineTimer := time.NewTimer(150 * time.Millisecond)
	defer deadlineTimer.Stop()
collect:
	for len(deadlines) < 3 {
		select {
		case deadline := <-recording.readDeadlines:
			deadlines = append(deadlines, deadline)
		case <-deadlineTimer.C:
			break collect
		}
	}

	if len(deadlines) < 3 {
		t.Fatalf("read deadlines = %v, want header deadline, clear, and streaming deadline", deadlines)
	}

	downstreamClient.Close()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("proxyExplicitRequest() did not exit after downstream close")
	}
}

type recordingConn struct {
	net.Conn
	readDeadlines  chan time.Time
	writeDeadlines chan time.Time
}

func (c *recordingConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines <- t
	return c.Conn.SetReadDeadline(t)
}

func (c *recordingConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlines <- t
	return c.Conn.SetWriteDeadline(t)
}
