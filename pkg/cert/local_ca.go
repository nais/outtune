package cert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type localCA struct {
	caCertificate *tls.Certificate
}

func NewLocalCA(caCertificate *tls.Certificate) CA {
	return &localCA{
		caCertificate: caCertificate,
	}
}

func (g *localCA) MakeCert(_ context.Context, serial string, keyPem []byte) (string, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMilli()),
		Subject: pkix.Name{
			Organization:       []string{"NAV"},
			Country:            []string{"NO"},
			OrganizationalUnit: []string{"naisdevice"},
			CommonName:         fmt.Sprintf("naisdevice - %s is out of tune", serial),
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: g.caCertificate.Leaf.AuthorityKeyId,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, g.caCertificate.Leaf, keyPem, g.caCertificate.PrivateKey)
	if err != nil {
		return "", err
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	if err != nil {
		return "", fmt.Errorf("pem encode cert: %w", err)
	}

	return certPEM.String(), nil
}

func LocalCAInit() error {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(69),
		Subject: pkix.Name{
			Organization:       []string{"NAV"},
			OrganizationalUnit: []string{"naisdevice"},
			Country:            []string{"NO"},
			CommonName:         "naisdevice-root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	caCertFile, err := os.OpenFile("ca.pem", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	caCertKeyFile, err := os.OpenFile("ca.key", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	err = pem.Encode(caCertFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return err
	}

	err = pem.Encode(caCertKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return err
	}

	return nil
}
