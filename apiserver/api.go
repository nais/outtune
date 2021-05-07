package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"github.com/go-chi/chi"
	"github.com/nais/outtune/pkg/apiserver"
	"github.com/nais/outtune/pkg/cert"
	log "github.com/sirupsen/logrus"
	"net/http"
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

	generatedCert, err := cert.MakeCert(request.Context(), cReq.Email, publicKey)
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

func (a *api) getCert(writer http.ResponseWriter, request *http.Request) {
	pubKeyFromUrl := request.URL.Query().Get("public_key")
	publicKey, err := base64.StdEncoding.DecodeString(pubKeyFromUrl)
	if err != nil {
		log.Errorf("base64 decode public key: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	oid := request.Context().Value("oid").(string)
	generatedCert, err := cert.MakeCert(request.Context(), oid, publicKey)
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

func (a *api) oauth2Callback(writer http.ResponseWriter, _ *http.Request) {

}

func New(validator func(next http.Handler) http.Handler) chi.Router {
	api := &api{}
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		r.Use(validator)
		r.Post("/cert", api.cert)
		r.Get("/cert", api.getCert)
	})

	r.Get("/isalive", api.observability)
	r.Get("/isready", api.observability)

	r.Get("/oauth2/callback", api.oauth2Callback)

	return r
}
