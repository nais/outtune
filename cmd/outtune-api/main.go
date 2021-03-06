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

func main() {
	localCAInit := flag.Bool("local-ca-init", false, "Initialize new local CA, then exit")
	localCAEnabled := flag.Bool("local-ca-enabled", false, "Enable local CA")
	localCACertFile := flag.String("local-ca-cert", "ca.pem", "Local CA cert")
	localCAKeyFile := flag.String("local-ca-key", "ca.key", "Local CA key")
	flag.Parse()

	if *localCAInit {
		err := cert.LocalCAInit(*localCACertFile, *localCAKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("Successfully initialized ca")
		return
	}

	var localCA cert.CA

	if *localCAEnabled {
		caCertAndKey, err := tls.LoadX509KeyPair(*localCACertFile, *localCAKeyFile)
		if err != nil {
			log.Fatal(err)
		}

		localCA = cert.NewLocalCA(&caCertAndKey)
	}

	router := apiserver.New(localCA)
	fmt.Println("running @", "0.0.0.0:8080")
	fmt.Println(http.ListenAndServe("0.0.0.0:8080", router))
}
