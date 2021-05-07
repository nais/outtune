package main

import (
	"fmt"
	"github.com/nais/outtune/apiserver"
	"github.com/nais/outtune/apiserver/azure/discovery"
	"github.com/nais/outtune/apiserver/azure/validate"
	"github.com/nais/outtune/apiserver/config"
	"github.com/prometheus/common/log"
	"net/http"
	"os"
)

func envOrBust(name string) string {
	value := os.Getenv(name)
	if len(value) == 0 {
		log.Fatalf("required env var %s not found", name)
	}
	return value
}

func main() {
	azureConfig := config.Azure{
		ClientID:     envOrBust("AZURE_APP_CLIENT_ID"),
		DiscoveryURL: envOrBust("AZURE_APP_WELL_KNOWN_URL"),
		ClientSecret: envOrBust("AZURE_APP_CLIENT_SECRET"),
		TenantId:     envOrBust("AZURE_APP_TENANT_ID"),
	}
	certs, err := discovery.FetchCertificates(azureConfig)
	if err != nil {
		log.Fatalf("fetch certs: %v", err)
	}
	jwtValidator := validate.JWTValidator(certs, azureConfig.ClientID)
	validator := validate.Validator(azureConfig, jwtValidator)
	router := apiserver.New(validator)
	fmt.Println("running @", "localhost:8080")
	fmt.Println(http.ListenAndServe("localhost:8080", router))
}