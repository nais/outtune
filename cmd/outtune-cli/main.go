package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/nais/outtune/pkg/apiserver"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
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
			Type:  "RSA PRIVATE KEY",
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
	var apiUrl string
	flag.StringVar(&email, "email", "", "cert owner email (required)")
	flag.StringVar(&apiUrl, "apiurl", "https://outtune-api.prod-gcp.nais.io", "url to the api (optional)")
	flag.Parse()

	if email == "" {
		flag.Usage()
		log.Fatal("email is required")
	}

	privateKey, err := getPrivateKey()
	if err != nil {
		log.Fatalf("get private key: %v", err)
	}

	publicKeyPem, err := publicKeytoPem(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("get public key pem: %v", err)
	}

	certReq := apiserver.CertRequest{Serial: email, PublicKeyPem: base64.StdEncoding.EncodeToString(publicKeyPem)}
	jsonPayload, err := json.Marshal(certReq)
	if err != nil {
		log.Fatalf("encode json request: %v", err)
	}

	response, err := http.Post(apiUrl+"/cert", "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		log.Fatalf("make cert request: %v", err)
	}
	var certResponse apiserver.CertResponse
	err = json.NewDecoder(response.Body).Decode(&certResponse)
	if err != nil {
		log.Fatalf("unmarshal response json: %v", err)
	}

	//fmt.Println(certResponse.CertPem)
	certBlock, _ := pem.Decode([]byte(certResponse.CertPem))

	cert := &x509.Certificate{Raw: certBlock.Bytes}

	encode, err := pkcs12.Encode(rand.Reader, privateKey, cert, nil, "password")
	if err != nil {
		log.Fatalf("encoding cert and key: %v", err)
	}

	fmt.Println(string(encode))
}
