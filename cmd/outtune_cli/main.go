package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/nais/outtune/pkg/cert"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
)

const (
	PrivateKeyFileName = "key.pem"
)

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

func main() {
	var email string
	flag.StringVar(&email, "email", "", "cert owner email (required)")
	flag.Parse()

	if email == "" {
		flag.Usage()
		fmt.Println("\nemail is required")
		os.Exit(2)
	}

	ctx := context.Background()
	privateKey, err :=  getPrivateKey()
	if err != nil {
		log.Errorf("get private key: %w", err)
		os.Exit(1)
	}

	publicKeyPem, err := publicKeytoPem(&privateKey.PublicKey)
	if err != nil {
		log.Errorf("get public key pem: %w", err)
		os.Exit(1)
	}
	pemCertificate, err := cert.MakeCert(ctx, email, publicKeyPem)
	if err != nil {
		log.Errorf("generate pemCertificate: %v", err)
		os.Exit(1)
	}

	log.Infoln("Generated Certificate:")
	log.Infof("%v", pemCertificate)
}
