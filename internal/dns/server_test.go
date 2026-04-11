package dns

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
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

func TestForwarderDoesNotEmitHostnameEventWhenParsingFails(t *testing.T) {
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

	invalidQuery := []byte{0xde, 0xad, 0xbe}
	if _, err := client.Write(invalidQuery); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	select {
	case got := <-events:
		t.Fatalf("unexpected hostname event = %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestForwarderReturnsNXDOMAINWhenHostnameIsDenied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upstreamCalls := 0
	srv, err := Start(ctx, Config{
		ListenAddr: "127.0.0.1:0",
		Upstreams:  []string{"127.0.0.1:53535"},
		AllowQuery: func(hostname string) bool {
			return hostname != "blocked.example.com"
		},
	}, Deps{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			upstreamCalls++
			t.Fatalf("DialContext() should not be called for denied DNS queries")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("udp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	query := buildDNSQuery(t, []string{"blocked.example.com"})
	if _, err := client.Write(query); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if upstreamCalls != 0 {
		t.Fatalf("upstreamCalls = %d, want 0 for denied query", upstreamCalls)
	}

	resp := buf[:n]
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Fatalf("response id = %#x, want %#x", got, 0x1234)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Fatalf("response flags = %#x, want response bit set", flags)
	}
	if got := flags & 0x000f; got != 0x0003 {
		t.Fatalf("response rcode = %#x, want NXDOMAIN", got)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
		t.Fatalf("ancount = %d, want 0", got)
	}
}

func TestForwarderReportsResolvedIPsFromAllowedResponse(t *testing.T) {
	upstreamAddr, upstreamShutdown := startFakeUpstream(t, func(query []byte) []byte {
		return buildDNSAResponse(t, query, "allowed.example.com", []string{"93.184.216.34", "93.184.216.35"})
	})
	defer upstreamShutdown()

	resolved := make(chan Resolution, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := Start(ctx, Config{
		ListenAddr: "127.0.0.1:0",
		Upstreams:  []string{upstreamAddr},
		AllowQuery: func(hostname string) bool {
			return hostname == "allowed.example.com"
		},
		OnResolved: func(event Resolution) {
			resolved <- event
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

	query := buildDNSQuery(t, []string{"allowed.example.com"})
	if _, err := client.Write(query); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	select {
	case event := <-resolved:
		if event.Hostname != "allowed.example.com" {
			t.Fatalf("Resolution.Hostname = %q, want %q", event.Hostname, "allowed.example.com")
		}
		want := []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("93.184.216.35"),
		}
		if len(event.IPs) != len(want) {
			t.Fatalf("Resolution.IPs = %#v, want %#v", event.IPs, want)
		}
		for i := range want {
			if event.IPs[i] != want[i] {
				t.Fatalf("Resolution.IPs[%d] = %v, want %v", i, event.IPs[i], want[i])
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for resolved IP callback")
	}
}

func TestForwarderReturnsEmptySuccessForAllowedAAAAInEnforceMode(t *testing.T) {
	upstreamCalls := 0
	upstreamAddr, upstreamShutdown := startFakeUpstream(t, func(query []byte) []byte {
		upstreamCalls++
		return buildDNSAResponse(t, query, "registry-1.docker.io", []string{"93.184.216.34"})
	})
	defer upstreamShutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := Start(ctx, Config{
		ListenAddr: "127.0.0.1:0",
		Upstreams:  []string{upstreamAddr},
		AllowQuery: func(hostname string) bool {
			return hostname == "registry-1.docker.io"
		},
	}, Deps{
		Mode:      "enforce",
		GatewayIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	client, err := net.Dial("udp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	query := buildDNSQueryWithType(t, []string{"registry-1.docker.io"}, 28)
	if _, err := client.Write(query); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if upstreamCalls != 0 {
		t.Fatalf("upstreamCalls = %d, want 0 for enforce AAAA query", upstreamCalls)
	}

	resp := buf[:n]
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Fatalf("response flags = %#x, want response bit set", flags)
	}
	if got := flags & 0x000f; got != 0 {
		t.Fatalf("response rcode = %#x, want NOERROR", got)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
		t.Fatalf("ancount = %d, want 0", got)
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
	return buildDNSQueryWithType(t, names, 1)
}

func buildDNSQueryWithType(t *testing.T, names []string, qtype uint16) []byte {
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
		query = append(query, 0x00) // root
		query = binary.BigEndian.AppendUint16(query, qtype)
		query = append(query, 0x00, 0x01) // QCLASS IN
	}
	return query
}

func buildDNSAResponse(t *testing.T, query []byte, hostname string, ips []string) []byte {
	t.Helper()

	response := append([]byte(nil), query...)
	flags := binary.BigEndian.Uint16(response[2:4])
	flags |= 0x8000
	flags &^= 0x000f
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(ips)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)

	for _, rawIP := range ips {
		addr, err := netip.ParseAddr(rawIP)
		if err != nil {
			t.Fatalf("ParseAddr(%q) error = %v", rawIP, err)
		}
		if !addr.Is4() {
			t.Fatalf("buildDNSAResponse() only supports IPv4 test answers, got %q", rawIP)
		}
		response = appendDNSName(response, hostname)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint32(response, 60)
		response = binary.BigEndian.AppendUint16(response, 4)
		response = append(response, addr.AsSlice()...)
	}

	return response
}

func appendDNSName(buf []byte, hostname string) []byte {
	for _, label := range splitLabels(hostname) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

func splitLabels(hostname string) [][]byte {
	parts := make([][]byte, 0, 4)
	start := 0
	for i := 0; i <= len(hostname); i++ {
		if i != len(hostname) && hostname[i] != '.' {
			continue
		}
		if start < i {
			parts = append(parts, []byte(hostname[start:i]))
		}
		start = i + 1
	}
	return parts
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
