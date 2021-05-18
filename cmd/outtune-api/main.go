package main

import (
	"fmt"
	"github.com/nais/outtune/apiserver"
	"net/http"
)

func main() {
	router := apiserver.New()
	fmt.Println("running @", "localhost:8080")
	fmt.Println(http.ListenAndServe("localhost:8080", router))
}
