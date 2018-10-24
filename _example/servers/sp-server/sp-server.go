package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pressly/saml"
	"github.com/pkg/errors"
)

var (
	flagInitiatedBy = flag.String("initiated-by", "", "Either idp or sp")
	flagListenAddr  = flag.String("listen-addr", "127.0.0.1:1113", "Bind to address")
	flagPublicURL   = flag.String("public-url", "http://127.0.0.1:1113", "Service's public URL")

	flagMetadataURL = flag.String("idp-metadata-url", "http://127.0.0.1:1117/metadata.xml", "IdP's metadata URL")
	flagRelayState  = flag.String("relay-state", "", "Relay state")

	flagSSOServiceBinding = flag.String("sso-service-binding", "redirect", "SSO service binding")

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
		http.Error(w, err.Error(), 400)
		return
	}
	assertion, err := serviceProvider.AssertResponse(r.Form.Get("SAMLResponse"))
	if err != nil {
		http.Error(w, err.Error(), 400)
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
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf8")
	w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	w.Write(xml)
}

func authRequestHandler(w http.ResponseWriter, r *http.Request) {
	successRedirectURL := r.FormValue("redirect_url")

	switch serviceProvider.IdPSSOServiceBinding {

	case saml.HTTPRedirectBinding:
		idpRedirectURL, err := serviceProvider.AuthnRequestURL(successRedirectURL)
		if err != nil {
			http.Error(w, err.Error(), 500)
		}
		log.Printf("Redirecting to IdP with SAMLRequest: %+v", idpRedirectURL)
		w.Header().Add("Location", idpRedirectURL)
		w.WriteHeader(http.StatusFound)

	case saml.HTTPPostBinding:
		samlRequest, err := serviceProvider.NewPostSAMLRequest()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		payload := fmt.Sprintf(`
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
	<body onload="document.forms[0].submit()">
		<form action="%s" method="post">
			<div>
				<input type="hidden" name="RelayState" value="%s" />
				<input type="hidden" name="SAMLRequest" value="%s" />
			</div>
	  </form>
	</body>
</html>
	`, serviceProvider.IdPSSOServiceURL, successRedirectURL, samlRequest)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(payload))

	}
	http.Error(w, errors.Errorf("invalid sso service binding: %v", serviceProvider.IdPSSOServiceBinding).Error(), 500)
	return
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
		ACSURL:      *flagPublicURL + acsPath,

		SecurityOpts: saml.SecurityOpts{
			AllowSelfSignedCert: true,
		},
	}

	serviceProvider.IdPMetadataURL = *flagMetadataURL
	idpMetadata, err := serviceProvider.ParseIdPMetadata()
	if err != nil {
		log.Fatal(errors.Wrap(err, "failed to parse idp metadata"))
	}
	serviceProvider.IdPMetadata = idpMetadata

	var binding string
	switch *flagSSOServiceBinding {
	case "redirect":
		binding = saml.HTTPRedirectBinding
	case "post":
		binding = saml.HTTPPostBinding
	}
	ssoService := idpMetadata.SSOService(binding)
	if ssoService != nil {
		serviceProvider.IdPSSOServiceBinding = ssoService.Binding
		serviceProvider.IdPSSOServiceURL = ssoService.Location
	}

	idpCert := idpMetadata.Cert()
	serviceProvider.IdPPubkeyPEM = idpCert
	serviceProvider.IdPEntityID = idpMetadata.EntityID

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
