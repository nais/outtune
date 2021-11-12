package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/nais/outtune/pkg/apiserver"
	"github.com/nais/outtune/pkg/cert"
)

var (
	caProvider      string
	localCACertFile string
	localCAKeyFile  string
	localCAInit     bool
)

func init() {
	flag.BoolVar(&localCAInit, "local-ca-init", false, "Initialize new local CA, then exit")
	flag.StringVar(&localCACertFile, "local-ca-cert", "ca.pem", "Local CA cert")
	flag.StringVar(&localCAKeyFile, "local-ca-key", "ca.key", "Local CA key")
	flag.StringVar(&caProvider, "ca-provider", "google", "CA provider (google or local)")
	flag.Parse()
}

func main() {
	if localCAInit {
		err := cert.LocalCAInit()
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("Successfully initialized ca")
		return
	}

	var ca cert.CA
	if caProvider == "google" {
		ca = cert.NewGoogleCA()
	} else {
		caCertAndKey, err := tls.LoadX509KeyPair(localCACertFile, localCAKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		ca = cert.NewLocalCA(&caCertAndKey)
	}

	router := apiserver.New(ca)
	fmt.Println("running @", "localhost:8080")
	fmt.Println(http.ListenAndServe("localhost:8080", router))
}
