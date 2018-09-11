package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/goware/saml"
	"github.com/pressly/api/lib/ws"
)

var (
	flagInitiatedBy = flag.String("initiated-by", "", "Either idp or sp")
	flagListenAddr  = flag.String("listen-addr", "127.0.0.1:1113", "Bind to address")
	flagPublicURL   = flag.String("public-url", "http://127.0.0.1:1113", "Service's public URL")

	flagMetadataURL = flag.String("idp-metadata-url", "http://127.0.0.1:1117/metadata.xml", "IdP's metadata URL")
	flagRelayState  = flag.String("relay-state", "", "Relay state")

	flagPubCert = flag.String("pubkey-cert-pem", "", "Load public key from PEM file")
	flagPrivKey = flag.String("privkey-pem", "", "Load private key from PEM file")

	flagHelp = flag.Bool("help", false, "Display help")
)

var (
	serviceProvider saml.ServiceProvider
)

const (
	metadataPath = "/metadata.xml"
	acsPath      = "/saml/acs"
)

func accessGrantedHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		ws.Respond(w, r, 400, err)
		return
	}
	assertion, err := serviceProvider.AssertResponse(r.Form.Get("SAMLResponse"))
	if err != nil {
		ws.Respond(w, r, 400, err)
		return
	}

	r.ParseForm()

	relayState := r.Form.Get("RelayState")

	log.Printf("Login OK, RelayState: %v", relayState)

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

func logHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("URL: %s", r.URL.String())
		next.ServeHTTP(w, r)
	})
}

func metadataHandler(w http.ResponseWriter, r *http.Request) {
	xml, err := serviceProvider.MetadataXML()
	if err != nil {
		ws.Respond(w, r, 500, err)
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf8")
	w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	w.Write(xml)
}

func authRequestHandler(w http.ResponseWriter, r *http.Request) {
	successRedirectURL := r.FormValue("redirect_url")

	idpRedirectURL, err := serviceProvider.AuthnRequestURL(successRedirectURL)
	if err != nil {
		ws.Respond(w, r, 500, err)
		return
	}

	w.Header().Add("Location", idpRedirectURL)
	w.WriteHeader(http.StatusFound)
}

func setRelayState(nextFn func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "saml.RelayState", *flagRelayState)
		log.Printf("Setting RelayState: %s", *flagRelayState)
		nextFn(w, r.WithContext(ctx))
	}
}

func main() {

	flag.Parse()

	if (flagHelp != nil && *flagHelp) || flagInitiatedBy == nil {
		flag.PrintDefaults()
		return
	}

	if flagListenAddr == nil || flagPublicURL == nil || flagRelayState == nil {
		flag.PrintDefaults()
		return
	}

	if flagPubCert == nil || *flagPubCert == "" {
		log.Fatal("Missing -pubkey-cert-pem")
	}

	if flagPrivKey == nil || *flagPrivKey == "" {
		log.Fatal("Missing -privkey-pem")
	}

	serviceProvider = saml.ServiceProvider{
		CertFile: *flagPubCert,
		KeyFile:  *flagPrivKey,

		IdPMetadataURL: *flagMetadataURL,

		MetadataURL: *flagPublicURL + metadataPath,
		AcsURL:      *flagPublicURL + acsPath,

		SecurityOpts: saml.SecurityOpts{
			AllowSelfSignedCert: true,
		},
	}

	r := chi.NewRouter()
	r.Use(logHandler)

	r.Get(metadataPath, metadataHandler)

	r.Post(acsPath, accessGrantedHandler)

	log.Printf("Test SP server listening at %s (%s)", *flagListenAddr, *flagPublicURL)
	switch *flagInitiatedBy {
	case "sp":
		r.Get("/", setRelayState(authRequestHandler))
		log.Printf("Go to %s to begin the SP initiated login.", *flagPublicURL)
	}

	log.Fatal(http.ListenAndServe(*flagListenAddr, r))
}
