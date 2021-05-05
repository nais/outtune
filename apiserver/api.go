package apiserver

import (
	"github.com/go-chi/chi"
	"net/http"
)

type api struct {
	value string
}

func (a *api) cert(writer http.ResponseWriter, request *http.Request) {
	response := "YO!"
	writer.Write([]byte (response))
}

func New() chi.Router {
	api := &api{}

	r := chi.NewRouter()

	r.Get("/cert", api.cert)

	return r
}
