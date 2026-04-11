package dns

import (
	"context"
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

	if got != "100.96.0.1:53" {
		t.Fatalf("ResolveListenAddr() = %q, want %q", got, "100.96.0.1:53")
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
