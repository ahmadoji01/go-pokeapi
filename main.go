package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/contrib/cors"
	"gitlab.com/kitalabs/go-2gaijin/config"
	"gitlab.com/kitalabs/go-2gaijin/router"
)

func redirectTLS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+config.DomainName+":443"+r.RequestURI, http.StatusMovedPermanently)
}

func setupCORS() cors.Config {
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowedMethods = []string{"POST", "GET", "PUT", "PATCH", "DELETE"}
	config.AllowedHeaders = []string{"*"}
	return config
}

func main() {

	router := router.Router()

	if config.IsProduction {
		go func() {
			if err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS)); err != nil {
				log.Fatalf("ListenAndServe error: %v", err)
			}
		}()
		log.Fatal(http.ListenAndServeTLS(":443", "keys/cert.pem", "keys/key.pem", router))
	} else {
		log.Fatal(http.ListenAndServe(":8080", router))
	}
}