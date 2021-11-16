package cert

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

type CA interface {
	MakeCert(ctx context.Context, serial string, keyPem []byte) (string, error)
}

func PublicKeytoPem(key *rsa.PublicKey) ([]byte, error) {
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
