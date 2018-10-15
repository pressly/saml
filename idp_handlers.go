package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"text/template"

	"github.com/pkg/errors"
)

// MetadataHandler generates and serves the IdP's metadata.xml file.
func (idp *IdentityProvider) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	metadata, err := idp.Metadata()
	if err != nil {
		writeErr(w, errors.Wrap(err, "failed to generate metadata"))
		return
	}
	out, err := xml.MarshalIndent(metadata, "", "\t")
	if err != nil {
		writeErr(w, errors.Wrap(err, "failed to build metadata"))
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
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	lr := &LoginRequest{
		spMetadataURL: spMetadataURL,
		idp:           idp,
		authFn:        authFn,
		metadata:      metadata,
	}
	return lr, nil
}

func (idp *IdentityProvider) GenerateResponse(samlRequest, relayState string, sess *Session, address string) ([]byte, error) {
	var authnRequest AuthnRequest
	if err := xml.Unmarshal([]byte(samlRequest), &authnRequest); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal saml request")
	}

	idpAuthnRequest := &IdpAuthnRequest{
		IDP:     idp,
		Address: address,
		Request: authnRequest,
	}

	if err := idpAuthnRequest.MakeAssertion(sess); err != nil {
		return nil, errors.Wrap(err, "failed to make assertion")
	}

	if err := idpAuthnRequest.MarshalAssertion(); err != nil {
		return nil, errors.Wrap(err, "failed to marshal assertion")
	}

	if err := idpAuthnRequest.MakeResponse(); err != nil {
		return nil, errors.Wrap(err, "failed to build response")
	}

	buf, err := xml.MarshalIndent(idpAuthnRequest.Response, "", "\t")
	if err != nil {
		return nil, errors.Wrap(err, "failed to format response")
	}

	form := redirectForm{
		FormAction:   idpAuthnRequest.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient,
		RelayState:   relayState, // RelayState is passed as is.
		SAMLResponse: base64.StdEncoding.EncodeToString(buf),
	}

	formTpl, err := template.New("").Parse(redirectFormTemplate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create form")
	}

	formBuf := bytes.NewBuffer(nil)
	if err := formTpl.Execute(formBuf, form); err != nil {
		return nil, errors.Wrap(err, "failed to build form")
	}
	return formBuf.Bytes(), nil

}

func writeErr(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}
