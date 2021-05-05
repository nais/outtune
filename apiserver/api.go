package apiserver

import (
	"encoding/json"
	"github.com/go-chi/chi"
	"github.com/nais/outtune/pkg/cert"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type api struct {
	value string
}

type CertRequest struct {
	Email string `json:"email"`
	PublicKeyPem string `json:"public_key_pem"`
}

type CertResponse struct {
	CertPem string `json:"cert_pem"`
}

func (a *api) cert(writer http.ResponseWriter, request *http.Request) {
	var cReq CertRequest
	err := json.NewDecoder(request.Body).Decode(&cReq)

	if err != nil {
		log.Errorf("unmarshaling request: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	generatedCert, err := cert.MakeCert(cReq.Email)
	if err != nil {
		log.Errorf("generating cert: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(writer).Encode(CertResponse{CertPem: generatedCert})

}

func New() chi.Router {
	api := &api{}

	r := chi.NewRouter()

	r.Post("/cert", api.cert)

	return r
}
