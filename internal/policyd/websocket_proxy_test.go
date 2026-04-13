package policyd

import (
	"bytes"
	"testing"
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
}

func TestRewriteWebSocketProxyHeaderLeavesNonWebSocketRequestsUntouched(t *testing.T) {
	input := []byte("GET http://example.com/chat HTTP/1.1\r\nHost: example.com\r\n\r\n")

	got, rewritten := rewriteWebSocketProxyHeader(input)

	if rewritten {
		t.Fatal("rewritten = true, want false")
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("header = %q, want unchanged request", got)
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
