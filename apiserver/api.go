package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"github.com/go-chi/chi"
	"github.com/nais/outtune/pkg/apiserver"
	"github.com/nais/outtune/pkg/cert"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

type api struct {
	value string
}

func (a *api) cert(writer http.ResponseWriter, request *http.Request) {
	var cReq apiserver.CertRequest
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
	generatedCert, err := cert.MakeCert(request.Context(), trimmedSerial, publicKey)
	if err != nil {
		log.Errorf("generating cert: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(writer).Encode(apiserver.CertResponse{CertPem: generatedCert})
	if err != nil {
		log.Errorf("writing response: %v", err)
	}
}

func (a *api) observability(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func New() chi.Router {
	api := &api{}
	r := chi.NewRouter()

	r.Post("/cert", api.cert)

	r.Get("/isalive", api.observability)
	r.Get("/isready", api.observability)

	return r
}
