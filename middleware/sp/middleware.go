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

// Package sp provides tools for buildin an SP such as serving metadata,
// authenticating an assertion and building assertions for IdPs.
package sp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/goware/saml"
	"github.com/goware/saml/xmlsec"
)

// AccessFunction is a function that returns an HTTP handler that is called
// after a successful assertion validation.
type AccessFunction func(*saml.Assertion) func(http.ResponseWriter, *http.Request)

// AuthFunction is an authentication handler that returns true after a
// successful authentication.
type AuthFunction func(http.ResponseWriter, *http.Request) bool

// Middleware represents a SP middleware.
type Middleware struct {
	sp *saml.ServiceProvider
}

// NewMiddleware creates a middleware based on the given service provider.
func NewMiddleware(sp *saml.ServiceProvider) *Middleware {
	if sp == nil {
		panic("SP cannot be a nil value.")
	}
	return &Middleware{sp: sp}
}

// ServeRequestAuth creates an authentication assert and makes the user send it
// to the IdP (via redirection).
func (m *Middleware) ServeRequestAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	destination, err := m.sp.GetIdPAuthResource()
	if err != nil {
		saml.Logf("GetIdPAuthResource: %v", err)
		internalErr(w, err)
		return
	}

	authnRequest, err := m.sp.MakeAuthenticationRequest(destination)
	if err != nil {
		saml.Logf("Failed to make auth request to %v: %v", destination, err)
		internalErr(w, err)
		return
	}

	buf, err := xml.MarshalIndent(authnRequest, "", "\t")
	if err != nil {
		saml.Logf("Failed to marshal auth request %v", err)
		internalErr(w, err)
		return
	}

	// RelayState is an opaque string that can be used to keep track of this
	// session on our side.
	var relayState string
	token := ctx.Value("saml.RelayState")
	if token != nil {
		relayState, _ = token.(string)
	}

	fbuf := bytes.NewBuffer(nil)
	fwri, err := flate.NewWriter(fbuf, flate.DefaultCompression)
	if err != nil {
		saml.Logf("Failed to build buffer %v", err)
		internalErr(w, err)
		return
	}

	_, err = fwri.Write(buf)
	if err != nil {
		saml.Logf("Failed to write to buffer %v", err)
		internalErr(w, err)
		return
	}
	fwri.Close()
	message := base64.StdEncoding.EncodeToString(fbuf.Bytes())

	redirectURL := destination + fmt.Sprintf(`?RelayState=%s&SAMLRequest=%s`, url.QueryEscape(relayState), url.QueryEscape(message))

	w.Header().Add("Location", redirectURL)
	w.WriteHeader(http.StatusFound)
	return
}

// ServeMetadata creates and serves a metadata XML file.
func (m *Middleware) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	metadata, err := m.sp.Metadata()
	if err != nil {
		saml.Logf("Failed to build metadata %v", err)
		internalErr(w, err)
		return
	}
	out, err := xml.MarshalIndent(metadata, "", "\t")
	if err != nil {
		saml.Logf("Failed to format metadata %v", err)
		internalErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf8")
	w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	w.Write(out)
}

func (m *Middleware) possibleResponseIDs() []string {
	responseIDs := []string{}
	if m.sp.AllowIdpInitiated {
		responseIDs = append(responseIDs, "")
	}
	return responseIDs
}

// ServeAcs creates an HTTP handler that can be used to authenticate and
// validate an assertion. If the assertion is valid the flow it passed to the
// given grantFn function.
func (m *Middleware) ServeAcs(grantFn AccessFunction) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		now := saml.Now()

		r.ParseForm()

		samlResponse := r.Form.Get("SAMLResponse")

		// This RelayState (if any) needs to be been validated by the invoker.
		relayState := r.Form.Get("RelayState")

		// TODO: Remove this when we're stable enough.
		saml.Logf("SAMLResponse -> %v", samlResponse)
		saml.Logf("relayState -> %v", relayState)

		_ = relayState // Don't know what to do with this yet.

		samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponse)
		if err != nil {
			saml.Logf("Failed to decode SAMLResponse %v", err)
			clientErr(w, err, errors.New("Malformed payload"))
			return
		}

		saml.Logf("SAMLResponse (XML) -> %v", string(samlResponseXML))

		var res saml.Response
		err = xml.Unmarshal(samlResponseXML, &res)
		if err != nil {
			saml.Logf("Failed to unmarshal SAMLResponse %v", err)
			clientErr(w, err, errors.New("Malformed XML"))
			return
		}

		_, err = m.sp.GetIdPMetadata()
		if err != nil {
			clientErr(w, fmt.Errorf("Unable to get metadata: %v", err), errors.New("Unable to get metadata"))
			return
		}

		// Validate message.

		if res.Destination != m.sp.AcsURL {
			clientErr(w, fmt.Errorf("Wrong ACS destination, expecting %q, got %q", m.sp.AcsURL, res.Destination), errors.New("Wrong ACS destination"))
			return
		}

		if res.IssueInstant.Add(saml.MaxIssueDelay).Before(now) {
			clientErr(w, fmt.Errorf("IssueInstant expired, got %v, current time is %v", res.IssueInstant, now), errors.New("IssueInstant expired"))
			return
		}

		if m.sp.IdPMetadata.EntityID != "" {
			if res.Issuer.Value != m.sp.IdPMetadata.EntityID {
				clientErr(w, fmt.Errorf("Issuer %q does not match expected entity ID %q", res.Issuer.Value, m.sp.IdPMetadata.EntityID), errors.New("Issuer does not match expected entity ID"))
				return
			}
		}

		if res.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
			clientErr(w, errors.New("Unexpected status code"), nil)
			return
		}

		expectedResponse := false
		responseIDs := m.possibleResponseIDs()
		for i := range responseIDs {
			if responseIDs[i] == res.InResponseTo {
				expectedResponse = true
			}
		}
		if len(responseIDs) == 1 && responseIDs[0] == "" {
			expectedResponse = true
		}
		if !expectedResponse && len(responseIDs) > 0 {
			clientErr(w, fmt.Errorf("Expecting a proper InResponseTo value, got %#v", responseIDs), nil)
			return
		}

		// Message verification.
		idpCertFile, err := m.sp.GetIdPCertFile()
		if err != nil {
			saml.Logf("Failed to get IDP cert: %v", err)
			internalErr(w, err)
			return
		}

		var assertion *saml.Assertion
		if res.EncryptedAssertion != nil {
			keyFile, err := m.sp.PrivkeyFile()
			if err != nil {
				saml.Logf("Failed to get private key: %v", err)
				internalErr(w, err)
				return
			}

			plainTextAssertion, err := xmlsec.Decrypt(res.EncryptedAssertion.EncryptedData, keyFile)
			if err != nil {
				if saml.IsSecurityException(err, &m.sp.SecurityOpts) {
					clientErr(w, err, errors.New("Unable to decrypt message"))
					return
				}
			}

			if err := xmlsec.Verify(plainTextAssertion, idpCertFile, "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"); err != nil {
				if saml.IsSecurityException(err, &m.sp.SecurityOpts) {
					saml.Logf("Failed to decrypt assertion: %q", plainTextAssertion)
					clientErr(w, err, errors.New("Unabe to verify assertion"))
					return
				}
			}

			assertion = &saml.Assertion{}
			if err := xml.Unmarshal(plainTextAssertion, assertion); err != nil {
				clientErr(w, err, errors.New("Unable to parse assertion"))
				return
			}
		} else {
			var assertionErr error

			idAttrs := []string{
				"urn:oasis:names:tc:SAML:2.0:protocol:Response",
				"urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
			}
			log.Printf("assertionErr")

			assertion = res.Assertion
			for _, idAttr := range idAttrs {
				err := xmlsec.Verify(samlResponseXML, idpCertFile, idAttr)
				log.Printf("idAttr: %v: %v", idAttr, err)
				if err != nil {
					if saml.IsSecurityException(err, &m.sp.SecurityOpts) {
						assertionErr = err
						break
					}
				}
			}

			if assertionErr != nil {
				clientErr(w, assertionErr, errors.New("Unable to verify assertion"))
				return
			}
		}

		if assertion == nil {
			clientErr(w, errors.New("Missing assertion"), nil)
			return
		}

		// Validate assertion.

		// Assertion's issue instant should not differ too much from the current
		// time.
		if assertion.IssueInstant.Add(saml.MaxIssueDelay).Before(now) {
			clientErr(w, fmt.Errorf("Assertion expired, got %v, time is %v", assertion.IssueInstant, now), errors.New("Assertion is expired"))
			return
		}

		if m.sp.IdPMetadata.EntityID != "" {
			if assertion.Issuer.Value != m.sp.IdPMetadata.EntityID {
				clientErr(w, fmt.Errorf("Assertion issuer %q does not match expected entity ID %q", assertion.Issuer.Value, m.sp.IdPMetadata.EntityID), errors.New("Assertion issuer does not match expected entity ID"))
				return
			}
		}

		if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != m.sp.AcsURL {
			clientErr(w, fmt.Errorf("Unexpected assertion recipient, expecting %q, got %q", m.sp.AcsURL, assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient), errors.New("Unexpected assertion recipient"))
			return
		}

		// The NotBefore and NotOnOrAfter attributes specify time limits on the
		// validity of the assertion within the context of its profile(s) of use.
		// They do not guarantee that the statements in the assertion will be
		// correct or accurate throughout the validity period. The NotBefore
		// attribute specifies the time instant at which the validity interval
		// begins. The NotOnOrAfter attribute specifies the time instant at which
		// the validity interval has ended. If the value for either NotBefore or
		// NotOnOrAfter is omitted, then it is considered unspecified.

		if validFrom := assertion.Conditions.NotBefore; !validFrom.IsZero() && validFrom.After(now) {
			clientErr(w, fmt.Errorf("Assertion conditions are not yet valid, got %v, current time is %v", validFrom, now), errors.New("Assertion conditions are not yet valid"))
			return
		}

		if validUntil := assertion.Conditions.NotOnOrAfter; !validUntil.IsZero() && validUntil.Before(now) {
			clientErr(w, fmt.Errorf("Assertion conditions already expired, got %v current time is %v", validUntil, now), errors.New("Assertion conditions already expired"))
			return
		}

		// A time instant at which the subject can no longer be confirmed. The time
		// value is encoded in UTC, as described in Section 1.3.3.
		//
		// Note that the time period specified by the optional NotBefore and
		// NotOnOrAfter attributes, if present, SHOULD fall within the overall
		// assertion validity period as specified by the element's NotBefore and
		// NotOnOrAfter attributes. If both attributes are present, the value for
		// NotBefore MUST be less than (earlier than) the value for NotOnOrAfter.

		if validUntil := assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter; validUntil.Before(now) {
			clientErr(w, fmt.Errorf("Assertion conditions already expired, got %v current time is %v", validUntil, now), errors.New("Assertion conditions already expired"))
			return
		}

		if assertion.Conditions.AudienceRestriction != nil {
			if assertion.Conditions.AudienceRestriction.Audience.Value != m.sp.MetadataURL {
				// clientErr(w, fmt.Errorf("Audience restriction mismatch, got %q, expecting %q", assertion.Conditions.AudienceRestriction.Audience.Value, m.sp.MetadataURL), errors.New("Audience restriction mismatch"))
				// return
			}
		}

		expectedResponse = false
		for i := range responseIDs {
			if responseIDs[i] == assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo {
				expectedResponse = true
			}
		}
		if len(responseIDs) == 1 && responseIDs[0] == "" {
			expectedResponse = true
		}

		if !expectedResponse && len(responseIDs) > 0 {
			clientErr(w, errors.New("Unexpected assertion InResponseTo value"), nil)
			return
		}

		assertionHandler := grantFn(assertion)
		assertionHandler(w, r)
	}
}

func clientErr(w http.ResponseWriter, privErr error, publicErr error) {
	saml.Logf("clientErr: private: %v, public: %v", privErr, publicErr)
	if publicErr == nil {
		publicErr = privErr
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(publicErr.Error()))
}

func internalErr(w http.ResponseWriter, err error) {
	saml.Logf("internalErr: %v", err)
	serverErr(w, err, errors.New("An internal error ocurred, please try again."))
}

func serverErr(w http.ResponseWriter, privErr error, publicErr error) {
	saml.Logf("serverErr: private: %v, public: %v", privErr, publicErr)
	if publicErr == nil {
		publicErr = privErr
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(publicErr.Error()))
}
