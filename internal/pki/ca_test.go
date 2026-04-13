package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"testing"
)

func TestNewRuntimeCAPopulatesRootPEM(t *testing.T) {
	ca, err := NewRuntimeCA("runtime-a")
	if err != nil {
		t.Fatalf("NewRuntimeCA() error = %v", err)
	}
	if len(ca.RootCertPEM) == 0 {
		t.Fatalf("RootCertPEM is empty")
	}
	if len(ca.RootKeyPEM) == 0 {
		t.Fatalf("RootKeyPEM is empty")
	}

	root := mustParseCert(t, ca.RootCertPEM)
	if !root.IsCA {
		t.Fatalf("root cert IsCA = false, want true")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root cert not self-signed: %v", err)
	}
}

func TestIssueLeafIncludesIPSANForLiteralIP(t *testing.T) {
	ca, err := NewRuntimeCA("runtime-a")
	if err != nil {
		t.Fatalf("NewRuntimeCA() error = %v", err)
	}

	certPEM, _, err := ca.IssueLeaf(LeafRequest{IP: netip.MustParseAddr("203.0.113.7")})
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v", err)
	}

	cert := mustParseCert(t, certPEM)
	if got := cert.IPAddresses[0].String(); got != "203.0.113.7" {
		t.Fatalf("leaf IP SAN = %q, want 203.0.113.7", got)
	}
}

func TestIssueLeafIncludesDNSSANForHostname(t *testing.T) {
	ca, err := NewRuntimeCA("runtime-a")
	if err != nil {
		t.Fatalf("NewRuntimeCA() error = %v", err)
	}

	certPEM, _, err := ca.IssueLeaf(LeafRequest{DNSName: "example.com"})
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v", err)
	}

	cert := mustParseCert(t, certPEM)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Fatalf("leaf DNS SANs = %v, want [example.com]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("leaf IP SANs = %v, want none", cert.IPAddresses)
	}
}

func mustParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("pem.Decode() = %#v, want CERTIFICATE", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert
}

