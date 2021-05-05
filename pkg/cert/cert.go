package cert

import (
	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
	"io/ioutil"
	mathrand "math/rand"
	"os"
	"strings"
	"time"
)

const (
	CAGoogleProject = "nais-device"
	CAGoogleProjectLocation = "europe-west1"
	PrivateKeyFileName = "key.pem"
)

func publicKeytoPem(key *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("error when dumping publickey: %w", err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	s := strings.Builder{}
	err = pem.Encode(&s, publicKeyBlock)
	if err != nil {
		return nil, fmt.Errorf("pem encode: %w", err)
	}

	return []byte(s.String()), nil
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	_, err := os.Stat(PrivateKeyFileName)

	if os.IsNotExist(err) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("create key: %v", err)
		}

		privateKeyBlock := &pem.Block{
			Type:  "",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}

		privatePem, err := os.Create(PrivateKeyFileName)
		if err != nil {
			return nil, fmt.Errorf("error when create: %w", err)
		}

		err = pem.Encode(privatePem, privateKeyBlock)
		if err != nil {
			return nil, fmt.Errorf("error when encode private pem: %w", err)
		}
		return privateKey, nil
	} else {
		file, err := os.Open(PrivateKeyFileName)
		if err != nil {
			return nil, fmt.Errorf("open file: %w", err)
		}
		privateKeyBytes, err := ioutil.ReadAll(file)

		block, rest := pem.Decode(privateKeyBytes)
		if block == nil {
			return nil, fmt.Errorf("invalid pem private key: decoded data is nil")
		}
		if len(rest) != 0 {
			log.Warnf("garbage found in %s:\n%s", PrivateKeyFileName, rest)
		}

		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
}

func MakeCert(ctx context.Context, email string, keyPem []byte) (string, error) {
	client, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return "", fmt.Errorf("create client: %w", err)
	}

	csr := &privatecapb.CreateCertificateRequest{
		Parent:        fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", CAGoogleProject, CAGoogleProjectLocation, "naisdevice"),
		CertificateId: fmt.Sprintf("CertId%d", mathrand.Uint64()),
		Certificate: &privatecapb.Certificate{
			Name: "CertName",
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{
							CountryCode:        "NO",
							Organization:       "NAV",
							OrganizationalUnit: "Utvikling",
						},
						CommonName: "CommonName",
						SubjectAltName: &privatecapb.SubjectAltNames{
							EmailAddresses: []string{email},
						},
					},
					ReusableConfig: &privatecapb.ReusableConfigWrapper{
						ConfigValues: &privatecapb.ReusableConfigWrapper_ReusableConfigValues{
							ReusableConfigValues: &privatecapb.ReusableConfigValues{
								KeyUsage: &privatecapb.KeyUsage{
									BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
										DigitalSignature: true,
									},
									ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
										ClientAuth: true,
									},
								},
							},
						},
					},
					PublicKey: &privatecapb.PublicKey{
						Type: privatecapb.PublicKey_PEM_RSA_KEY,
						Key: keyPem,
					},
				},
			},
			Lifetime: durationpb.New(time.Hour * 24 * 7),
			Labels:   map[string]string{
				"created-by": "outtune",
			},
		},
	}

	resp, err := client.CreateCertificate(ctx, csr)
	if err != nil {
		return "", fmt.Errorf("create cert: %w", err)
	}

	return resp.PemCertificate, nil
}
