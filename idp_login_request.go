package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"log"
	"net/http"
	"text/template"
)

var redirectFormTemplate = `<!DOCTYPE html>
<html>
	<head></head>
	<body>
		<form id="redirect" method="POST" action="{{.FormAction}}">
			<input type="hidden" name="RelayState" value="{{.RelayState}}" />
			<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />
		</form>
		<script type="text/javascript">
			document.getElementById("redirect").submit();
		</script>
	</body>
</html>`

// Authenticator defines an authentication function that returns a
// *saml.Session value.
type Authenticator func(w http.ResponseWriter, r *http.Request) (*Session, error)

type redirectForm struct {
	FormAction   string
	RelayState   string
	SAMLResponse string
}

// LoginRequest represents a login request that the IdP creates in order to try
// autenticating against a SP.
type LoginRequest struct {
	spMetadataURL string
	metadata      *Metadata
	authFn        Authenticator
	idp           *IdentityProvider
}

// PostForm creates and serves a form that is used to authenticate to the SP.
func (lr *LoginRequest) PostForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess, err := lr.authFn(w, r)
	if err != nil {
		log.Printf("authFn: %v", err)
		return
	}

	authnRequest := &AuthnRequest{}

	idpAuthnRequest := &IdpAuthnRequest{
		IDP:                     lr.idp,
		Address:                 r.RemoteAddr,
		Request:                 *authnRequest,
		ServiceProviderMetadata: lr.metadata,
	}

	if err = idpAuthnRequest.MakeAssertion(sess); err != nil {
		log.Printf("Failed to build assertion %v", err)
		writeErr(w, err)
		return
	}

	err = idpAuthnRequest.MarshalAssertion()
	if err != nil {
		log.Printf("Failed to marshal assertion %v", err)
		writeErr(w, err)
		return
	}

	err = idpAuthnRequest.MakeResponse()
	if err != nil {
		log.Printf("Failed to build response %v", err)
		writeErr(w, err)
		return
	}

	buf, err := xml.MarshalIndent(idpAuthnRequest.Response, "", "\t")
	if err != nil {
		log.Printf("Failed to format response %v", err)
		writeErr(w, err)
		return
	}

	// RelayState is an opaque string that can be used to keep track of this
	// session on our side.
	var relayState string
	token := ctx.Value("saml.RelayState")
	if token != nil {
		relayState, _ = token.(string)
	}

	form := redirectForm{
		FormAction:   lr.metadata.SPSSODescriptor.AssertionConsumerService[0].Location,
		RelayState:   relayState,
		SAMLResponse: base64.StdEncoding.EncodeToString(buf),
	}

	formTpl, err := template.New("").Parse(redirectFormTemplate)
	if err != nil {
		log.Printf("Failed to create form %v", err)
		writeErr(w, err)
		return
	}

	formBuf := bytes.NewBuffer(nil)
	if err := formTpl.Execute(formBuf, form); err != nil {
		log.Printf("Failed to build form %v", err)
		writeErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(formBuf.Bytes())
}
