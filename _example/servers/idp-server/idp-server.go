package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/pressly/saml"
	"github.com/pkg/errors"
	"github.com/pressly/chi"

	"time"
)

var (
	flagInitiatedBy = flag.String("initiated-by", "", "Either idp or sp")

	flagListenAddr = flag.String("listen-addr", "127.0.0.1:1117", "Bind to this address")
	flagPublicURL  = flag.String("public-url", "http://127.0.0.1:1117", "Service's public URL")

	flagMetadataURL = flag.String("sp-metadata-url", "http://127.0.0.1:1113/metadata.xml", "SP's metadata URL")
	flagRelayState  = flag.String("relay-state", "", "Relay state")

	flagEntityID = flag.String("entity-id", "TestIdP", "Entity ID")

	flagPubCert = flag.String("pubkey-cert-pem", "", "Load public key from PEM file")
	flagPrivKey = flag.String("privkey-pem", "", "Load private key from PEM file")

	flagHelp = flag.Bool("help", false, "Display help.")
)

const (
	metadataPath = "/metadata.xml"
	ssoPath      = "/idp/sso"
	initiatePath = "/idp/initiate"
)

type user struct {
	loginHandler string
	Password     string
}

var validUsers = []user{
	{
		loginHandler: "anakin",
		Password:     "skywalker",
	},
}

var (
	identityProvider saml.IdentityProvider
)

func spInitiatedLogin(w http.ResponseWriter, r *http.Request) {
	sess, err := authFn(w, r)
	if err != nil {
		http.Error(w, errors.Wrap(err, "failed to authenticate user").Error(), 500)
		return
	}

	ctx := r.Context()
	relayState := ctx.Value("relayState").(string)
	samlRequest := ctx.Value("samlRequest").(string)

	samlResponse, err := identityProvider.GenerateResponse(samlRequest, relayState, sess, r.RemoteAddr)
	if err != nil {
		http.Error(w, errors.Wrap(err, "failed to process saml request").Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(samlResponse)
}

func redirectBindingCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		values := r.URL.Query()
		ctx = context.WithValue(ctx, "relayState", values.Get("RelayState"))
		ctx = context.WithValue(ctx, "samlRequest", values.Get("SAMLRequest"))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func postBindingCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if err := r.ParseForm(); err != nil {
			http.Error(w, errors.Wrap(err, "failed to parse form").Error(), 400)
			return
		}
		ctx = context.WithValue(ctx, "relayState", r.Form.Get("RelayState"))
		ctx = context.WithValue(ctx, "samlRequest", r.Form.Get("SAMLRequest"))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authFn validates user credentials and creates a
// saml.Session.
func authFn(w http.ResponseWriter, r *http.Request) (*saml.Session, error) {
	user, pass, ok := r.BasicAuth()
	if ok {
		for _, u := range validUsers {
			if u.loginHandler == user && u.Password == pass {
				sess := &saml.Session{
					UserID:       "anakin",
					UserEmail:    "anakin@example.org",
					UserFullname: "Anakin Skywalker",
					CreateTime:   time.Now(),
				}
				return sess, nil
			}
		}
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="IdP credentials"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))

	return nil, errors.New("Failed to authenticate user.")
}

// initiateLogin creates a message for the SP.
func initiateLogin(idp *saml.IdentityProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		spMetadataURL := r.Form.Get("metadata_url")
		if spMetadataURL == "" {
			log.Printf("Missing metadata_url")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		if flagRelayState != nil {
			ctx = context.WithValue(ctx, "saml.RelayState", *flagRelayState)
		}

		req, err := idp.NewLoginRequest(spMetadataURL, authFn)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		req.PostForm(w, r.WithContext(ctx))
	}
}

// displayLoginForm displays a simple login form where
// you can choose a SP.
func displayLoginForm(w http.ResponseWriter, r *http.Request) {
	loginForm := `<!DOCTYPE html>
	<html>
		<head>
		</head>
		<body>
			<h2>Select SP</h2>
			<form action="` + *flagPublicURL + initiatePath + `">
				<select name="metadata_url">
					<option value="">(Choose one)</option>
					<option value="` + *flagMetadataURL + `">` + *flagMetadataURL + `</option>
				</select>
				<button type="submit">OK</button>
			</form>
		</body>
	</html>`
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(loginForm))
}

func logHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("URL: %s", r.URL.String())
		next.ServeHTTP(w, r)
	})
}

func main() {
	flag.Parse()

	if (flagHelp != nil && *flagHelp) || flagInitiatedBy == nil {
		flag.PrintDefaults()
		return
	}

	if flagListenAddr == nil || flagEntityID == nil || flagMetadataURL == nil {
		flag.PrintDefaults()
		return
	}

	switch *flagInitiatedBy {
	case "idp":
	case "sp":
	default:
		flag.PrintDefaults()
		return
	}

	if (flagHelp != nil && *flagHelp) ||
		flagListenAddr == nil ||
		flagEntityID == nil ||
		flagMetadataURL == nil {
		flag.PrintDefaults()
		return
	}

	if flagPubCert == nil || *flagPubCert == "" {
		log.Fatal("Missing -pubkey-cert-pem")
	}

	if flagPrivKey == nil || *flagPrivKey == "" {
		log.Fatal("Missing -privkey-pem")
	}

	identityProvider = saml.IdentityProvider{
		CertFile: *flagPubCert,
		KeyFile:  *flagPrivKey,

		MetadataURL: *flagPublicURL + metadataPath,
		SSOURL:      *flagPublicURL + ssoPath,

		SPMetadataURL: *flagMetadataURL,
		EntityID:      *flagEntityID,

		SecurityOpts: saml.SecurityOpts{
			AllowSelfSignedCert: true,
		},
	}

	r := chi.NewRouter()
	r.Use(logHandler)

	r.Get(metadataPath, identityProvider.MetadataHandler)

	log.Printf("Test IdP server listening at %s (%s)", *flagListenAddr, *flagPublicURL)
	switch *flagInitiatedBy {
	case "idp":
		r.Get("/", displayLoginForm)
		r.Get(initiatePath, initiateLogin(&identityProvider))
		log.Printf("Go to %s to begin the IdP initiated login.", *flagPublicURL)
	case "sp":
		r.With(redirectBindingCtx).Get(ssoPath, spInitiatedLogin)
		r.With(postBindingCtx).Post(ssoPath, spInitiatedLogin)
	}

	log.Fatal(http.ListenAndServe(*flagListenAddr, r))
}
