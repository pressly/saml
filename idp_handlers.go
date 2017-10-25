package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"text/template"
)

// ServeMetadata generates and serves the IdP's metadata.xml file.
func (idp *IdentityProvider) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	metadata, err := idp.Metadata()
	if err != nil {
		Logf("Failed to generate metadata: %v", err)
		writeErr(w, err)
		return
	}
	out, err := xml.MarshalIndent(metadata, "", "\t")
	if err != nil {
		Logf("Failed to build metadata: %v", err)
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf8")
	w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	w.Write(out)
}

// NewLoginRequest creates a login request against an SP.
func (idp *IdentityProvider) NewLoginRequest(spMetadataURL string, authFn Authenticator) (*LoginRequest, error) {
	metadata, err := GetMetadata(spMetadataURL)
	if err != nil {
		Logf("Failed to get metadata: %v", err)
		return nil, err
	}
	lr := &LoginRequest{
		spMetadataURL: spMetadataURL,
		idp:           idp,
		authFn:        authFn,
		metadata:      metadata,
	}
	return lr, nil
}

// ServeSSO creates and serves a SSO assertion based on a request.
func (idp *IdentityProvider) ServeSSO(authFn Authenticator) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := authFn(w, r)
		if err != nil {
			Logf("authFn: %v", err)
			return
		}

		values := r.URL.Query()

		relayState := values.Get("RelayState")
		samlRequest := values.Get("SAMLRequest")

		data, err := base64.StdEncoding.DecodeString(samlRequest)
		if err != nil {
			Logf("Failed to decode SAMLRequest: %v", err)
			writeErr(w, err)
			return
		}
		buf, err := ioutil.ReadAll(flate.NewReader(bytes.NewBuffer(data)))
		if err != nil {
			Logf("Failed to read SAMLRequest: %v", err)
			writeErr(w, err)
			return
		}

		var authnRequest AuthnRequest
		err = xml.Unmarshal(buf, &authnRequest)
		if err != nil {
			Logf("Failed to unmarshal SAMLRequest: %v", err)
			writeErr(w, err)
			return
		}

		idpAuthnRequest := &IdpAuthnRequest{
			IDP:         idp,
			HTTPRequest: r,
			Request:     authnRequest,
		}

		err = idpAuthnRequest.MakeAssertion(sess)
		if err != nil {
			Logf("Failed to make assertion: %v", err)
			writeErr(w, err)
			return
		}

		err = idpAuthnRequest.MarshalAssertion()
		if err != nil {
			Logf("Failed to marshal assertion: %v", err)
			writeErr(w, err)
			return
		}

		err = idpAuthnRequest.MakeResponse()
		if err != nil {
			Logf("Failed to build response: %v", err)
			writeErr(w, err)
			return
		}

		buf, err = xml.MarshalIndent(idpAuthnRequest.Response, "", "\t")
		if err != nil {
			Logf("Failed to format response: %v", err)
			writeErr(w, err)
			return
		}

		form := redirectForm{
			FormAction:   idpAuthnRequest.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient,
			RelayState:   relayState, // RelayState is passed as is.
			SAMLResponse: base64.StdEncoding.EncodeToString(buf),
		}

		formTpl, err := template.New("").Parse(redirectFormTemplate)
		if err != nil {
			Logf("Failed to create form: %v", err)
			writeErr(w, err)
			return
		}

		formBuf := bytes.NewBuffer(nil)
		if err := formTpl.Execute(formBuf, form); err != nil {
			Logf("Failed to build form: %v", err)
			writeErr(w, err)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(formBuf.Bytes())
	}
}

func writeErr(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}
