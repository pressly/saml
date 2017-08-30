// MIT License
//
// Copyright (c) 2017 Pressly Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package idp

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"text/template"

	"github.com/goware/saml"
)

// LoginRequest represents a login request that the IdP creates in order to try
// autenticating against a SP.
type LoginRequest struct {
	spMetadataURL string
	metadata      *saml.Metadata
	authFn        Authenticator
	m             *Middleware
}

// PostForm creates and serves a form that is used to authenticate to the SP.
func (lr *LoginRequest) PostForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess, err := lr.authFn(w, r)
	if err != nil {
		saml.Logf("authFn: %v", err)
		return
	}

	authnRequest := &saml.AuthnRequest{}

	idpAuthnRequest := &saml.IdpAuthnRequest{
		IDP:                     lr.m.idp,
		HTTPRequest:             r,
		Request:                 *authnRequest,
		ServiceProviderMetadata: lr.metadata,
	}

	if err = idpAuthnRequest.MakeAssertion(sess); err != nil {
		saml.Logf("Failed to build assertion %v", err)
		writeErr(w, err)
		return
	}

	err = idpAuthnRequest.MarshalAssertion()
	if err != nil {
		saml.Logf("Failed to marshal assertion %v", err)
		writeErr(w, err)
		return
	}

	err = idpAuthnRequest.MakeResponse()
	if err != nil {
		saml.Logf("Failed to build response %v", err)
		writeErr(w, err)
		return
	}

	buf, err := xml.MarshalIndent(idpAuthnRequest.Response, "", "\t")
	if err != nil {
		saml.Logf("Failed to format response %v", err)
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
		saml.Logf("Failed to create form %v", err)
		writeErr(w, err)
		return
	}

	formBuf := bytes.NewBuffer(nil)
	if err := formTpl.Execute(formBuf, form); err != nil {
		saml.Logf("Failed to build form %v", err)
		writeErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(formBuf.Bytes())
}
