package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pressly/saml"
	"github.com/pressly/saml/middleware/sp"
)

var (
	flagListenAddr = flag.String("listen-addr", "127.0.0.1:1113", "Bind to address")
	flagPublicURL  = flag.String("public-url", "http://127.0.0.1:1113", "Service's public URL")

	flagMetadataURL = flag.String("idp-metadata-url", "http://127.0.0.1:1117/metadata.xml", "IdP's metadata URL")
	flagRelayState  = flag.String("relay-state", "", "Relay state")

	flagPubCert = flag.String("pubkey-cert-pem", "", "Load public key from PEM file")
	flagPrivKey = flag.String("privkey-pem", "", "Load private key from PEM file")

	flagHelp = flag.Bool("help", false, "Display help")
)

func accessGranted(assertion *saml.Assertion) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]interface{}{}
		for _, attr := range assertion.AttributeStatement.Attributes {
			values := []string{}
			for _, value := range attr.Values {
				values = append(values, value.Value)
			}
			key := attr.FriendlyName
			if key == "" {
				key = attr.Name
			}
			claims[key] = values
		}
		buf, err := json.Marshal(claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(buf)
	}
}

func loggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("URL: %s", r.URL.String())
		ctx := context.WithValue(r.Context(), "saml.RelayState", *flagRelayState)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {

	flag.Parse()

	if (flagHelp != nil && *flagHelp) || flagListenAddr == nil || flagPublicURL == nil || flagRelayState == nil {
		flag.PrintDefaults()
		return
	}

	if flagPubCert == nil || *flagPubCert == "" {
		log.Fatal("Missing -pubkey-cert-pem")
	}

	if flagPrivKey == nil || *flagPrivKey == "" {
		log.Fatal("Missing -privkey-pem")
	}

	const (
		metadataPath = "/metadata.xml"
		acsPath      = "/saml/acs"
	)

	serviceProvider := saml.ServiceProvider{
		CertFile: *flagPubCert,
		KeyFile:  *flagPrivKey,

		IdPMetadataURL: *flagMetadataURL,

		MetadataURL: *flagPublicURL + metadataPath,
		AcsURL:      *flagPublicURL + acsPath,

		SecurityOpts: saml.SecurityOpts{
			AllowSelfSignedCert: true,
		},
	}

	middleware := sp.NewMiddleware(&serviceProvider)

	r := chi.NewRouter()
	r.Use(loggingHandler)

	r.Get(metadataPath, middleware.ServeMetadata)
	r.Post(acsPath, middleware.ServeAcs(accessGranted))

	log.Printf("Test SP server listening at %s", *flagListenAddr)
	log.Fatal(http.ListenAndServe(*flagListenAddr, r))
}
