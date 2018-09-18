package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
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
	data, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode saml request")
	}
	buf, err := ioutil.ReadAll(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to read saml request")
	}

	var authnRequest AuthnRequest
	err = xml.Unmarshal(buf, &authnRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal saml request")
	}

	idpAuthnRequest := &IdpAuthnRequest{
		IDP:     idp,
		Address: address,
		Request: authnRequest,
	}

	err = idpAuthnRequest.MakeAssertion(sess)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make assertion")
	}

	err = idpAuthnRequest.MarshalAssertion()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal assertion")
	}

	err = idpAuthnRequest.MakeResponse()
	if err != nil {
		return nil, errors.Wrap(err, "failed to build response")
	}

	buf, err = xml.MarshalIndent(idpAuthnRequest.Response, "", "\t")
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
