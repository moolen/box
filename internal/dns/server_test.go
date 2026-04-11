package dns

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestAutoBindInMonitorModeUsesGatewayIPAndDefaultPort(t *testing.T) {
	t.Parallel()

	got, err := ResolveListenAddr("auto", "monitor", "100.96.0.1")
	if err != nil {
		t.Fatalf("ResolveListenAddr() error = %v", err)
	}

	if got != "100.96.0.1:1053" {
		t.Fatalf("ResolveListenAddr() = %q, want %q", got, "100.96.0.1:1053")
	}
}

func TestExplicitBindPortInMonitorModeStillUsesGatewayIP(t *testing.T) {
	t.Parallel()

	got, err := ResolveListenAddr("127.0.0.1:2053", "monitor", "100.96.0.1")
	if err != nil {
		t.Fatalf("ResolveListenAddr() error = %v", err)
	}

	if got != "100.96.0.1:2053" {
		t.Fatalf("ResolveListenAddr() = %q, want %q", got, "100.96.0.1:2053")
	}
}

func TestForwarderReturnsUpstreamAnswer(t *testing.T) {
	upstreamAddr, upstreamShutdown := startFakeUpstream(t, func(query []byte) []byte {
		response := make([]byte, 0, len(query)+1)
		response = append(response, query...)
		response = append(response, 0x7f)
		return response
	})
	defer upstreamShutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := Start(ctx, Config{
		ListenAddr: "127.0.0.1:0",
		Upstreams:  []string{upstreamAddr},
	}, Deps{})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("udp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	want := []byte{0xde, 0xad, 0xbe, 0xef}
	if _, err := client.Write(want); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	got := buf[:n]
	want = append(want, 0x7f)
	if string(got) != string(want) {
		t.Fatalf("forwarded response = %v, want %v", got, want)
	}
}

func TestForwarderShutdownClosesListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := Start(ctx, Config{
		ListenAddr: "127.0.0.1:0",
		Upstreams:  []string{"127.0.0.1:5300"},
	}, Deps{})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	addr := srv.Addr().String()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("ListenPacket() after shutdown error = %v, want nil", err)
	}
	_ = ln.Close()
}

func TestParseQueryHostnameReturnsFirstQuestionName(t *testing.T) {
	t.Parallel()

	query := buildDNSQuery(t, []string{"first.example.com", "second.example.com"})

	got, ok := parseQueryHostname(query)
	if !ok {
		t.Fatalf("parseQueryHostname() ok = false, want true")
	}
	if got != "first.example.com" {
		t.Fatalf("parseQueryHostname() = %q, want %q", got, "first.example.com")
	}
}

func TestForwarderEmitsHostnameEvent(t *testing.T) {
	upstreamAddr, upstreamShutdown := startFakeUpstream(t, func(query []byte) []byte {
		response := make([]byte, len(query))
		copy(response, query)
		return response
	})
	defer upstreamShutdown()

	events := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := Start(ctx, Config{
		ListenAddr: "127.0.0.1:0",
		Upstreams:  []string{upstreamAddr},
		OnQuery: func(hostname string) {
			events <- hostname
		},
	}, Deps{})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("udp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	query := buildDNSQuery(t, []string{"monitor.example.com"})
	if _, err := client.Write(query); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	select {
	case got := <-events:
		if got != "monitor.example.com" {
			t.Fatalf("event hostname = %q, want %q", got, "monitor.example.com")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for query event")
	}
}

func startFakeUpstream(t *testing.T, responder func(query []byte) []byte) (addr string, shutdown func()) {
	t.Helper()

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, client, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}

			query := make([]byte, n)
			copy(query, buf[:n])
			resp := responder(query)
			_, _ = ln.WriteTo(resp, client)
		}
	}()

	return ln.LocalAddr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func buildDNSQuery(t *testing.T, names []string) []byte {
	t.Helper()
	if len(names) == 0 {
		t.Fatalf("buildDNSQuery() requires at least one name")
	}

	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(query[2:4], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(query[4:6], uint16(len(names)))

	for _, name := range names {
		for _, label := range splitDomainName(name) {
			query = append(query, byte(len(label)))
			query = append(query, label...)
		}
		query = append(query, 0x00)       // root
		query = append(query, 0x00, 0x01) // QTYPE A
		query = append(query, 0x00, 0x01) // QCLASS IN
	}
	return query
}

func splitDomainName(name string) []string {
	labels := make([]string, 0, 4)
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}
