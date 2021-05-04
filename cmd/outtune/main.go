package main

import (
	"flag"
	"fmt"
	"github.com/nais/outtune/pkg/cert"
	log "github.com/sirupsen/logrus"
	"os"
)

func main() {
	var email string
	flag.StringVar(&email, "email", "", "cert owner email (required)")
	flag.Parse()

	if email == "" {
		flag.Usage()
		fmt.Println("\nemail is required")
		os.Exit(1)
	}

	pem, err := cert.MakeCert(email)
	if err != nil {
		log.Errorf("making cert: %v", err)
		os.Exit(1)
	}

	log.Infof("cert: %v", pem)
}