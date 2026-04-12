package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor-net/internal/config"
)

func TestHTTPProxyForwardsAndEmitsEvent(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	var (
		upstreamReq []byte
		acceptDone  = make(chan struct{})
	)
	go func() {
		defer close(acceptDone)

		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		upstreamReq = append([]byte(nil), buf[:n]...)

		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan Event, 1)
	srv, err := StartHTTP(ctx, ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		OnEvent: func(ev Event) {
			events <- ev
		},
		ResolveUpstream: func(net.Conn) (string, error) {
			return upstream.Addr().String(), nil
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	req := "GET /hello?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Contains(resp, []byte("\r\n\r\nok")) {
		t.Fatalf("response = %q, want body %q", string(resp), "ok")
	}

	select {
	case ev := <-events:
		if ev.Protocol != "http" {
			t.Fatalf("Event.Protocol = %q, want %q", ev.Protocol, "http")
		}
		if ev.Hostname != "example.com" {
			t.Fatalf("Event.Hostname = %q, want %q", ev.Hostname, "example.com")
		}
		if ev.Method != "GET" {
			t.Fatalf("Event.Method = %q, want %q", ev.Method, "GET")
		}
		if ev.Path != "/hello" {
			t.Fatalf("Event.Path = %q, want %q", ev.Path, "/hello")
		}
		if ev.Host != "example.com" {
			t.Fatalf("Event.Host = %q, want %q", ev.Host, "example.com")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event")
	}

	<-acceptDone
	if !bytes.HasPrefix(upstreamReq, []byte("GET /hello?q=1 HTTP/1.1\r\n")) {
		t.Fatalf("forwarded request line = %q, want origin-form path", string(bytes.SplitN(upstreamReq, []byte("\r\n"), 2)[0]))
	}
	if !bytes.Contains(upstreamReq, []byte("Host: example.com")) {
		t.Fatalf("forwarded request = %q, want Host header", string(upstreamReq))
	}
}

func TestHTTPProxySupportsCONNECTTunneling(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	dialedAddr := make(chan string, 1)
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)

		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		if string(buf) != "ping" {
			t.Errorf("upstream payload = %q, want %q", string(buf), "ping")
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan Event, 1)
	srv, err := StartHTTP(ctx, ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			select {
			case dialedAddr <- address:
			default:
			}
			var d net.Dialer
			return d.DialContext(ctx, network, upstream.Addr().String())
		},
		OnEvent: func(ev Event) {
			events <- ev
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := client.Write([]byte(connectReq)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 128)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !bytes.Contains(resp[:n], []byte("200 Connection Established")) {
		t.Fatalf("CONNECT response = %q, want 200 Connection Established", string(resp[:n]))
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("Write(tunnel) error = %v", err)
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("ReadFull(tunnel) error = %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("tunnel response = %q, want %q", string(buf), "pong")
	}

	select {
	case ev := <-events:
		if ev.Protocol != "http" {
			t.Fatalf("Event.Protocol = %q, want %q", ev.Protocol, "http")
		}
		if ev.Host != "example.com:443" {
			t.Fatalf("Event.Host = %q, want %q", ev.Host, "example.com:443")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CONNECT event")
	}

	select {
	case addr := <-dialedAddr:
		if addr != "example.com:443" {
			t.Fatalf("DialContext() address = %q, want %q", addr, "example.com:443")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CONNECT dial")
	}

	<-upstreamDone
}

func TestHTTPProxyUsesRequestHostForExplicitHTTPRequest(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	dialedAddr := make(chan string, 1)
	upstreamReq := make(chan []byte, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		upstreamReq <- append([]byte(nil), buf[:n]...)

		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := StartHTTP(ctx, ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			select {
			case dialedAddr <- address:
			default:
			}
			var d net.Dialer
			return d.DialContext(ctx, network, upstream.Addr().String())
		},
		ResolveUpstream: func(net.Conn) (string, error) {
			return "127.0.0.1:1", nil
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	req := "GET http://example.com/hello?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Contains(resp, []byte("\r\n\r\nok")) {
		t.Fatalf("response = %q, want body %q", string(resp), "ok")
	}

	select {
	case addr := <-dialedAddr:
		if addr != "example.com:80" {
			t.Fatalf("DialContext() address = %q, want %q", addr, "example.com:80")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for explicit HTTP dial")
	}

	select {
	case forwarded := <-upstreamReq:
		if !bytes.HasPrefix(forwarded, []byte("GET /hello?q=1 HTTP/1.1\r\n")) {
			t.Fatalf("forwarded request line = %q, want origin-form path", string(bytes.SplitN(forwarded, []byte("\r\n"), 2)[0]))
		}
		if !bytes.Contains(forwarded, []byte("Host: example.com")) {
			t.Fatalf("forwarded request = %q, want Host header", string(forwarded))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for forwarded explicit HTTP request")
	}
}

func TestHTTPProxyFallsBackToHostHeaderWhenResolvedUpstreamLoopsToProxy(t *testing.T) {
	t.Parallel()

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	dialedAddr := make(chan string, 1)
	upstreamReq := make(chan []byte, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		upstreamReq <- append([]byte(nil), buf[:n]...)

		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := StartHTTP(ctx, ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			select {
			case dialedAddr <- address:
			default:
			}
			var d net.Dialer
			return d.DialContext(ctx, network, upstream.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	srvAddr := srv.Addr().String()
	srv.resolveUpstream = func(net.Conn) (string, error) {
		return srvAddr, nil
	}

	client, err := net.Dial("tcp", srvAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	req := "GET /hello?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Contains(resp, []byte("\r\n\r\nok")) {
		t.Fatalf("response = %q, want body %q", string(resp), "ok")
	}

	select {
	case addr := <-dialedAddr:
		if addr != "example.com:80" {
			t.Fatalf("DialContext() address = %q, want %q", addr, "example.com:80")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for origin-form fallback dial")
	}

	select {
	case forwarded := <-upstreamReq:
		if !bytes.HasPrefix(forwarded, []byte("GET /hello?q=1 HTTP/1.1\r\n")) {
			t.Fatalf("forwarded request line = %q, want origin-form path", string(bytes.SplitN(forwarded, []byte("\r\n"), 2)[0]))
		}
		if !bytes.Contains(forwarded, []byte("Host: example.com")) {
			t.Fatalf("forwarded request = %q, want Host header", string(forwarded))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for forwarded origin-form request")
	}
}

func TestHTTPProxyRejectsDisallowedHTTPRequest(t *testing.T) {
	t.Parallel()

	server, err := StartHTTP(context.Background(), ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		AllowHostname: func(host string) bool {
			return host == "allowed.example.com"
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() {
		_ = server.Close()
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET http://blocked.example.com/ HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !strings.Contains(string(response), "403 Forbidden") {
		t.Fatalf("proxy response = %q, want 403 Forbidden", string(response))
	}
}

func TestHTTPProxyRejectsDisallowedCONNECTRequest(t *testing.T) {
	t.Parallel()

	server, err := StartHTTP(context.Background(), ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		AllowHostname: func(host string) bool {
			return host == "allowed.example.com"
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() {
		_ = server.Close()
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !strings.Contains(string(response), "403 Forbidden") {
		t.Fatalf("proxy response = %q, want 403 Forbidden", string(response))
	}
}

func TestHTTPProxyRejectsDisallowedCONNECTPortViaAllowTarget(t *testing.T) {
	t.Parallel()

	server, err := StartHTTP(context.Background(), ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		AllowTarget: func(host string, port int) bool {
			return host == "allowed.example.com" && port == 443
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() {
		_ = server.Close()
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT allowed.example.com:8443 HTTP/1.1\r\nHost: allowed.example.com:8443\r\n\r\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !strings.Contains(string(response), "403 Forbidden") {
		t.Fatalf("proxy response = %q, want 403 Forbidden", string(response))
	}
}

func TestTLSPeekExtractsSNIAndForwardsClientHello(t *testing.T) {
	clientHello := buildClientHelloWithSNI("example.com")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	gotHello := make(chan []byte, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(clientHello))
		_, _ = io.ReadFull(conn, buf)
		gotHello <- buf

		_, _ = conn.Write([]byte("pong"))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan Event, 1)
	srv, err := StartTLS(ctx, ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		OnEvent: func(ev Event) {
			events <- ev
		},
		ResolveUpstream: func(net.Conn) (string, error) {
			return upstream.Addr().String(), nil
		},
	})
	if err != nil {
		t.Fatalf("StartTLS() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	if _, err := client.Write(clientHello); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("response = %q, want %q", string(buf), "pong")
	}

	select {
	case forwarded := <-gotHello:
		if !bytes.Equal(forwarded, clientHello) {
			t.Fatalf("forwarded ClientHello mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream ClientHello")
	}

	select {
	case ev := <-events:
		if ev.Protocol != "tls" {
			t.Fatalf("Event.Protocol = %q, want %q", ev.Protocol, "tls")
		}
		if ev.Hostname != "example.com" {
			t.Fatalf("Event.Hostname = %q, want %q", ev.Hostname, "example.com")
		}
		if ev.SNI != "example.com" {
			t.Fatalf("Event.SNI = %q, want %q", ev.SNI, "example.com")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event")
	}
}

func TestTransparentListenerFactoryUsesConfiguredPorts(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []string
	)

	httpLn, tlsLn, err := TransparentListenerFactory(config.TransparentProxyConfig{
		HTTPPort: 18080,
		TLSPort:  18443,
	}, func(network, address string) (net.Listener, error) {
		mu.Lock()
		calls = append(calls, fmt.Sprintf("%s %s", network, address))
		mu.Unlock()
		return net.Listen("tcp", "127.0.0.1:0")
	})
	if err != nil {
		t.Fatalf("TransparentListenerFactory() error = %v", err)
	}
	defer httpLn.Close()
	defer tlsLn.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("listen calls = %d, want 2", len(calls))
	}
	if calls[0] != "tcp :18080" {
		t.Fatalf("first listen = %q, want %q", calls[0], "tcp :18080")
	}
	if calls[1] != "tcp :18443" {
		t.Fatalf("second listen = %q, want %q", calls[1], "tcp :18443")
	}
}

func TestStartHTTPCloseDoesNotHangWithActiveUpstream(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	upstreamAccepted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(upstreamAccepted)
		<-releaseUpstream
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := StartHTTP(ctx, ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		ResolveUpstream: func(net.Conn) (string, error) {
			return upstream.Addr().String(), nil
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	req := "GET /hang HTTP/1.1\r\nHost: hang.test\r\nConnection: keep-alive\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	select {
	case <-upstreamAccepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream accept")
	}

	done := make(chan error, 1)
	go func() {
		done <- srv.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Close() hung with active upstream connection")
	}

	close(releaseUpstream)
}

func TestStartHTTPCloseCancelsBlockedDial(t *testing.T) {
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := StartHTTP(ctx, ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		ResolveUpstream: func(net.Conn) (string, error) {
			return "198.51.100.1:443", nil
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			close(dialCanceled)
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("StartHTTP() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	req := "GET /dial-block HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for dial to start")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- srv.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Close() hung while dial was blocked")
	}

	select {
	case <-dialCanceled:
	case <-time.After(2 * time.Second):
		t.Fatalf("blocked dial was not canceled")
	}
}

func buildClientHelloWithSNI(host string) []byte {
	hostBytes := []byte(host)

	serverName := make([]byte, 0, 1+2+len(hostBytes))
	serverName = append(serverName, 0x00)
	serverName = append(serverName, byte(len(hostBytes)>>8), byte(len(hostBytes)))
	serverName = append(serverName, hostBytes...)

	serverNameList := make([]byte, 0, 2+len(serverName))
	serverNameList = append(serverNameList, byte(len(serverName)>>8), byte(len(serverName)))
	serverNameList = append(serverNameList, serverName...)

	extBody := serverNameList
	ext := make([]byte, 0, 4+len(extBody))
	ext = append(ext, 0x00, 0x00)
	ext = append(ext, byte(len(extBody)>>8), byte(len(extBody)))
	ext = append(ext, extBody...)

	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x01)
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}
