package envoy

import (
	"strings"
	"testing"
)

func TestRenderBootstrapIncludesExplicitTransparentAndDNSListeners(t *testing.T) {
	cfg := BootstrapConfig{
		NodeID:          "runtime-a",
		ExplicitPort:    19001,
		TransparentPort: 19002,
		DNSPort:         19053,
		AuthzAddress:    "127.0.0.1:20001",
	}

	content, err := RenderBootstrap(cfg)
	if err != nil {
		t.Fatalf("RenderBootstrap() error = %v", err)
	}

	for _, want := range []string{
		"19001",
		"19002",
		"19053",
		"ext_authz",
		"dynamic_forward_proxy",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("bootstrap missing %q\ncontent=%s", want, content)
		}
	}
}

func TestRenderBootstrapRejectsInvalidAuthzAddress(t *testing.T) {
	_, err := RenderBootstrap(BootstrapConfig{
		NodeID:          "runtime-a",
		ExplicitPort:    19001,
		TransparentPort: 19002,
		DNSPort:         19053,
		AuthzAddress:    "missing-port",
	})
	if err == nil {
		t.Fatal("RenderBootstrap() error = nil, want invalid authz address rejection")
	}
}
