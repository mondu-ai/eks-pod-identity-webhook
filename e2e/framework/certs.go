// Package framework provides utilities for end-to-end testing of the webhook.
package framework

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// WebhookCertificates contains PEM-encoded certificates and keys for webhook TLS.
type WebhookCertificates struct {
	CACert     []byte // PEM-encoded CA certificate
	CAKey      []byte // PEM-encoded CA private key
	ServerCert []byte // PEM-encoded server certificate
	ServerKey  []byte // PEM-encoded server private key
}

// GenerateWebhookCertificates generates self-signed CA and server certificates
// for webhook TLS authentication.
func GenerateWebhookCertificates(namespace, serviceName string) (*WebhookCertificates, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"eks-pod-identity-webhook"},
			CommonName:   "eks-pod-identity-webhook-ca",
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate server serial number: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"eks-pod-identity-webhook"},
			CommonName:   serviceName,
		},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{
			serviceName,
			fmt.Sprintf("%s.%s", serviceName, namespace),
			fmt.Sprintf("%s.%s.svc", serviceName, namespace),
			fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, namespace),
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	return &WebhookCertificates{
		CACert:     pemEncodeCert(caCertDER),
		CAKey:      pemEncodeKey(caKey),
		ServerCert: pemEncodeCert(serverCertDER),
		ServerKey:  pemEncodeKey(serverKey),
	}, nil
}

// pemEncodeCert encodes a DER-encoded certificate to PEM format.
func pemEncodeCert(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

// pemEncodeKey encodes an RSA private key to PEM format.
func pemEncodeKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}
