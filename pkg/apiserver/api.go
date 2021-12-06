package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	log "github.com/sirupsen/logrus"

	"github.com/nais/outtune/pkg/cert"
)

func certHandler(ca cert.CA) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		var cReq CertRequest
		err := json.NewDecoder(request.Body).Decode(&cReq)

		if err != nil {
			log.Errorf("unmarshaling request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		publicKey, err := base64.StdEncoding.DecodeString(cReq.PublicKeyPem)
		if err != nil {
			log.Errorf("base64 decoding: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		trimmedSerial := strings.Replace(cReq.Serial, "\n", "", -1)
		generatedCert, err := ca.MakeCert(request.Context(), trimmedSerial, publicKey)
		if err != nil {
			log.Errorf("generating cert: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Infof("(%s) Returning cert for serial: %s", request.URL.Path, cReq.Serial)

		err = json.NewEncoder(writer).Encode(CertResponse{CertPem: generatedCert})
		if err != nil {
			log.Errorf("writing response: %v", err)
		}
	}
}

func observability(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func New(localCA, googleCA cert.CA) chi.Router {
	r := chi.NewRouter()

	if localCA != nil {
		r.Post("/local/cert", certHandler(localCA))
	}
	if googleCA != nil {
		r.Post("/google/cert", certHandler(googleCA))
		r.Post("/cert", certHandler(googleCA))
	}

	r.Get("/isalive", observability)
	r.Get("/isready", observability)

	return r
}
