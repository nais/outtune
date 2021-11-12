package cert

import (
	"context"
	"fmt"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/google/uuid"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	CAGoogleProject         = "nais-device"
	CAGoogleProjectLocation = "europe-north1"
	CAName                  = "naisdevice-root"
)

type googleCA struct {
}

func NewGoogleCA() CA {
	return &googleCA{}
}

func (g *googleCA) MakeCert(ctx context.Context, serial string, keyPem []byte) (string, error) {
	client, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return "", fmt.Errorf("create client: %w", err)
	}

	csr := &privatecapb.CreateCertificateRequest{
		Parent:        fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", CAGoogleProject, CAGoogleProjectLocation, CAName),
		CertificateId: fmt.Sprintf("%s_%d_%d", serial, time.Now().Unix(), uuid.New().ID()),
		Certificate: &privatecapb.Certificate{
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{
							Organization:       "NAV",
							CountryCode:        "NO",
							OrganizationalUnit: "naisdevice",
						},
						CommonName: fmt.Sprintf("naisdevice - %s is out of tune", serial),
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
						Key:  keyPem,
					},
				},
			},
			Lifetime: durationpb.New(time.Hour * 24),
			Labels: map[string]string{
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