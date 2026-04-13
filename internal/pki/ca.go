package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"time"
)

// RuntimeCA is an in-memory, self-signed root CA intended for ephemeral runtimes.
type RuntimeCA struct {
	RootCertPEM []byte
	RootKeyPEM  []byte

	rootCert *x509.Certificate
	rootKey  *rsa.PrivateKey
}

type LeafRequest struct {
	// Exactly one of DNSName or IP must be provided.
	DNSName string
	IP      netip.Addr
}

func NewRuntimeCA(runtimeID string) (*RuntimeCA, error) {
	if runtimeID == "" {
		return nil, errors.New("runtime id is empty")
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: runtimeID,
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)})

	return &RuntimeCA{
		RootCertPEM: certPEM,
		RootKeyPEM:  keyPEM,
		rootCert:    rootCert,
		rootKey:     rootKey,
	}, nil
}

func (ca *RuntimeCA) IssueLeaf(req LeafRequest) (certPEM []byte, keyPEM []byte, _ error) {
	if ca == nil || ca.rootCert == nil || ca.rootKey == nil {
		return nil, nil, errors.New("ca not initialized")
	}

	hasDNS := req.DNSName != ""
	hasIP := req.IP.IsValid()
	if hasDNS == hasIP {
		return nil, nil, errors.New("exactly one of DNSName or IP must be set")
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: leafCommonName(req),
		},
		NotBefore: now.Add(-1 * time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	if hasDNS {
		tmpl.DNSNames = []string{req.DNSName}
	} else {
		tmpl.IPAddresses = []net.IP{net.IP(req.IP.AsSlice())}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.rootCert, &leafKey.PublicKey, ca.rootKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	return certPEM, keyPEM, nil
}

func leafCommonName(req LeafRequest) string {
	if req.DNSName != "" {
		return req.DNSName
	}
	if req.IP.IsValid() {
		return req.IP.String()
	}
	return ""
}

func randSerial() (*big.Int, error) {
	// 128-bit random serial per common practice.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

