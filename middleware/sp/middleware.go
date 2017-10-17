// Package sp provides tools for buildin an SP such as serving metadata,
// authenticating an assertion and building assertions for IdPs.
package sp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/goware/saml"
	"github.com/goware/saml/xmlsec"
	"github.com/pkg/errors"
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

func parseFormAndKeepBody(r *http.Request) error {
	var buf bytes.Buffer

	// Fill buf while reading r.Body
	r.Body = ioutil.NopCloser(io.TeeReader(r.Body, &buf))

	// ParseForm reads all data from r.Body and empties it because it's a buffer.
	if err := r.ParseForm(); err != nil {
		return err
	}

	// Restore body so it can be read again.
	r.Body = ioutil.NopCloser(&buf)
	return nil
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
		internalErr(w, errors.Errorf("GetIdPAuthResource: %v", err))
		return
	}

	authnRequest, err := m.sp.MakeAuthenticationRequest(destination)
	if err != nil {
		internalErr(w, errors.Errorf("Failed to make auth request to %v: %v", destination, err))
		return
	}

	buf, err := xml.MarshalIndent(authnRequest, "", "\t")
	if err != nil {
		internalErr(w, errors.Errorf("Failed to marshal auth request %v", err))
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
		internalErr(w, errors.Errorf("Failed to build buffer %v", err))
		return
	}

	_, err = fwri.Write(buf)
	if err != nil {
		internalErr(w, errors.Errorf("Failed to write to buffer %v", err))
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
		internalErr(w, errors.Errorf("Failed to build metadata %v", err))
		return
	}
	out, err := xml.MarshalIndent(metadata, "", "\t")
	if err != nil {
		internalErr(w, errors.Errorf("Failed to format metadata %v", err))
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

		if err := parseFormAndKeepBody(r); err != nil {
			clientErr(w, r, errors.Wrap(err, "Unable to read POST data"))
		}

		samlResponse := r.Form.Get("SAMLResponse")

		// This RelayState (if any) needs to be been validated by the invoker.
		relayState := r.Form.Get("RelayState")

		// TODO: Remove this when we're stable enough.
		saml.Logf("SAMLResponse -> %v", samlResponse)
		saml.Logf("relayState -> %v", relayState)

		_ = relayState // Don't know what to do with this yet.

		samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponse)
		if err != nil {
			err = errors.Wrapf(err, "could not decode base64 payload: %s", samlResponse)
			clientErr(w, r, errors.Wrap(err, "Malformed payload"))
			return
		}

		saml.Logf("SAMLResponse (XML) -> %v", string(samlResponseXML))

		var res saml.Response
		err = xml.Unmarshal(samlResponseXML, &res)
		if err != nil {
			err = errors.Wrapf(err, "could not unmarshal XML document: %s", string(samlResponseXML))
			clientErr(w, r, errors.Wrap(err, "Malformed XML"))
			return
		}

		_, err = m.sp.GetIdPMetadata()
		if err != nil {
			clientErr(w, r, errors.Wrap(err, "unable to retrieve IdP metadata"))
			return
		}

		// Validate message.

		if res.Destination != m.sp.AcsURL {
			err := errors.Errorf("Wrong ACS destination, expecting %q, got %q", m.sp.AcsURL, res.Destination)
			clientErr(w, r, errors.Wrap(err, "Wrong ACS destination"))
			return
		}

		if m.sp.IdPMetadata.EntityID != "" {
			if res.Issuer.Value != m.sp.IdPMetadata.EntityID {
				err := errors.Errorf("Issuer %q does not match expected entity ID %q", res.Issuer.Value, m.sp.IdPMetadata.EntityID)
				clientErr(w, r, errors.Wrap(err, "Issuer does not match expected entity ID"))
				return
			}
		}

		if res.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
			err := errors.Errorf("Unexpected status code: %v", res.Status.StatusCode.Value)
			clientErr(w, r, errors.Wrap(err, "Unexpected status code"))
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
			err := errors.Errorf("Expecting a proper InResponseTo value, got %#v", responseIDs)
			clientErr(w, r, err)
			return
		}

		// Message verification.
		idpCertFile, err := m.sp.GetIdPCertFile()
		if err != nil {
			internalErr(w, errors.Errorf("Failed to get private key: %v", err))
			return
		}

		var assertion *saml.Assertion
		if res.EncryptedAssertion != nil {
			keyFile, err := m.sp.PrivkeyFile()
			if err != nil {
				internalErr(w, errors.Errorf("Failed to get private key: %v", err))
				return
			}

			plainTextAssertion, err := xmlsec.Decrypt(res.EncryptedAssertion.EncryptedData, keyFile)
			if err != nil {
				if saml.IsSecurityException(err, &m.sp.SecurityOpts) {
					clientErr(w, r, errors.Wrap(err, "Unable to decrypt message"))
					return
				}
			}

			if err := xmlsec.Verify(plainTextAssertion, idpCertFile, "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"); err != nil {
				if saml.IsSecurityException(err, &m.sp.SecurityOpts) {
					err = errors.Wrapf(err, "Failed to decrypt assertion: %q", plainTextAssertion)
					clientErr(w, r, errors.Wrap(err, "Unable to verify assertion"))
					return
				}
			}

			assertion = &saml.Assertion{}
			if err := xml.Unmarshal(plainTextAssertion, assertion); err != nil {
				clientErr(w, r, errors.Wrap(err, "Unable to parse assertion"))
				return
			}
		} else {
			var assertionErr error

			idAttrs := []string{
				"urn:oasis:names:tc:SAML:2.0:protocol:Response",
				"urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
			}

			assertion = res.Assertion
			for _, idAttr := range idAttrs {
				err := xmlsec.Verify(samlResponseXML, idpCertFile, idAttr)
				if err == nil {
					// No error, this message is OK
					break
				}

				// We got an error...
				if !saml.IsSecurityException(err, &m.sp.SecurityOpts) {
					// ...but it was not a security exception, so we ignore it and accept
					// the verification.
					break
				}

				// We had an error, let's try with the next ID.
				assertionErr = err
			}

			if assertionErr != nil {
				clientErr(w, r, errors.Wrap(assertionErr, "Unable to verify assertion"))
				return
			}
		}

		if assertion == nil {
			clientErr(w, r, errors.New("Missing assertion"))
			return
		}

		// Validate assertion.
		if m.sp.IdPMetadata.EntityID != "" {
			if assertion.Issuer.Value != m.sp.IdPMetadata.EntityID {
				err := errors.Errorf("Assertion issuer %q does not match expected entity ID %q", assertion.Issuer.Value, m.sp.IdPMetadata.EntityID)
				clientErr(w, r, errors.Wrap(err, "Assertion issuer does not match expected entity ID"))
				return
			}
		}

		if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != m.sp.AcsURL {
			err := errors.Errorf("Unexpected assertion recipient, expecting %q, got %q", m.sp.AcsURL, assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
			clientErr(w, r, errors.Wrapf(err, "Unexpected assertion recipient"))
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
		{
			validFrom := assertion.Conditions.NotBefore
			if !validFrom.IsZero() && validFrom.After(now.Add(saml.TimeTolerance)) {
				err := errors.Errorf("Assertion conditions are not valid yet, got %v, current time is %v", validFrom, now)
				clientErr(w, r, errors.Wrap(err, "Assertion conditions are not valid yet"))
				return
			}
		}

		{
			validUntil := assertion.Conditions.NotOnOrAfter
			if !validUntil.IsZero() && validUntil.Before(now.Add(-saml.TimeTolerance)) {
				err := errors.Errorf("Assertion conditions already expired, got %v current time is %v, extra time is %v", validUntil, now, now.Add(-saml.TimeTolerance))
				clientErr(w, r, errors.Wrap(err, "Assertion conditions already expired"))
				return
			}
		}

		// A time instant at which the subject can no longer be confirmed. The time
		// value is encoded in UTC, as described in Section 1.3.3.
		//
		// Note that the time period specified by the optional NotBefore and
		// NotOnOrAfter attributes, if present, SHOULD fall within the overall
		// assertion validity period as specified by the element's NotBefore and
		// NotOnOrAfter attributes. If both attributes are present, the value for
		// NotBefore MUST be less than (earlier than) the value for NotOnOrAfter.

		if validUntil := assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter; validUntil.Before(now.Add(-saml.TimeTolerance)) {
			err := errors.Errorf("Assertion conditions already expired, got %v current time is %v", validUntil, now)
			clientErr(w, r, errors.Wrap(err, "Assertion conditions already expired"))
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
			clientErr(w, r, errors.New("Unexpected assertion InResponseTo value"))
			return
		}

		assertionHandler := grantFn(assertion)
		assertionHandler(w, r)
	}
}

func publicErrorMessage(err error) string {
	// is there any better way to retrieve the error _message_ without the cause?
	msg := err.Error()
	parts := strings.SplitN(msg, ":", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return msg
}

func clientErr(w http.ResponseWriter, r *http.Request, err error) {
	publicError := publicErrorMessage(err)

	report := saml.InspectRequest(r)

	saml.Fatal(errors.Wrapf(err, "failed request: %s", report.String()))

	w.Header().Set("Content-Type", "text/plain; charset=utf8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(publicError))
}

func internalErr(w http.ResponseWriter, err error) {
	serverErr(w, errors.Wrap(err, "an internal error ocurred, please try again"))
}

func serverErr(w http.ResponseWriter, err error) {
	saml.Fatal(err)

	w.Header().Set("Content-Type", "text/plain; charset=utf8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(publicErrorMessage(err)))
}
