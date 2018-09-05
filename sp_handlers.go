// Package sp provides tools for buildin an SP such as serving metadata,
// authenticating an assertion and building assertions for IdPs.
package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

	"github.com/goware/saml/xmlsec"
	"github.com/pkg/errors"
)

// AuthnRequestURL creates SAML 2.0 AuthnRequest redirect URL,
// aka SP-initiated login (SP->IdP).
// The data is passed in the ?SAMLRequest query parameter and
// the value is base64 encoded and deflate-compressed <AuthnRequest>
// XML element. The final redirect destination that will be invoked
// on successful login is passed using ?RelayState query parameter.
func (sp *ServiceProvider) AuthnRequestURL(relayState string) (string, error) {
	destination, err := sp.GetIdPAuthResource()
	if err != nil {
		return "", errors.Wrap(err, "failed to get IdP destination")
	}

	authnRequest, err := sp.NewAuthnRequest(destination)
	if err != nil {
		return "", errors.Wrapf(err, "failed to make auth request to %v", destination)
	}

	buf, err := xml.MarshalIndent(authnRequest, "", "\t")
	if err != nil {
		return "", errors.Wrap(err, "Failed to marshal auth request")
	}

	flateBuf := bytes.NewBuffer(nil)
	flateWriter, err := flate.NewWriter(flateBuf, flate.DefaultCompression)
	if err != nil {
		return "", errors.Wrap(err, "failed to create flate writer")
	}

	_, err = flateWriter.Write(buf)
	if err != nil {
		return "", errors.Wrap(err, "failed to write to flate writer")
	}
	flateWriter.Close()
	message := base64.StdEncoding.EncodeToString(flateBuf.Bytes())

	redirectURL := destination + fmt.Sprintf(`?RelayState=%s&SAMLRequest=%s`, url.QueryEscape(relayState), url.QueryEscape(message))

	return redirectURL, nil
}

// MetadataXML returns SAML 2.0 Service Provider metadata XML.
func (sp *ServiceProvider) MetadataXML() ([]byte, error) {
	metadata, err := sp.Metadata()
	if err != nil {
		return nil, errors.Wrap(err, "could not build nor serve metadata XML")
	}

	out, err := xml.MarshalIndent(metadata, "", "\t")
	if err != nil {
		return nil, errors.Wrap(err, "could not format metadata")
	}

	return out, nil
}

func (sp *ServiceProvider) possibleResponseIDs() []string {
	responseIDs := []string{}
	if sp.AllowIdpInitiated {
		responseIDs = append(responseIDs, "")
	}
	return responseIDs
}

func (sp *ServiceProvider) verifySignature(plaintextMessage []byte) error {
	idpCertFile, err := sp.GetIdPCertFile()
	if err != nil {
		return err
	}

	err = xmlsec.Verify(plaintextMessage, idpCertFile, &xmlsec.ValidationOptions{
		DTDFile: sp.DTDFile,
	})
	if err == nil {
		// No error, this message is OK
		return nil
	}

	// We got an error...
	if !IsSecurityException(err, &sp.SecurityOpts) {
		// ...but it was not a security exception, so we ignore it and accept
		// the verification.
		return nil
	}

	return err
}

func (sp *ServiceProvider) AssertResponse(samlResponse string) (*Assertion, error) {
	now := Now()

	samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to base64-decode SAML response")
	}

	var res Response
	err = xml.Unmarshal(samlResponseXML, &res)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal XML document: %s", string(samlResponseXML))
	}

	// TODO: Do we really need to check the IdP metadata here?
	if _, err := sp.GetIdPMetadata(); err != nil {
		return nil, errors.Wrap(err, "unable to retrieve IdP metadata")
	}

	// Validate message.

	if res.Destination != sp.AcsURL {
		// Note: OneLogin triggers this error when the Recipient field
		// is left blank (or when not set to the correct ACS endpoint)
		// in the OneLogin SAML configuration page. OneLogin returns
		// Destination="{recipient}" in the SAML reponse in this case.
		return nil, errors.Errorf("Wrong ACS destination, expected %q, got %q", sp.AcsURL, res.Destination)
	}

	if sp.IdPMetadata.EntityID != "" {
		if res.Issuer == nil {
			return nil, errors.New(`Issuer does not match expected entity ID: Missing "Issuer" node`)
		}
		if res.Issuer.Value != sp.IdPMetadata.EntityID {
			return nil, errors.Errorf("Issuer does not match expected entity ID: expected %q, got %q", sp.IdPMetadata.EntityID, res.Issuer.Value)
		}
	}

	if res.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return nil, errors.Errorf("Unexpected status code: %v", res.Status.StatusCode.Value)
	}

	expectedResponse := false
	responseIDs := sp.possibleResponseIDs()
	for i := range responseIDs {
		if responseIDs[i] == res.InResponseTo {
			expectedResponse = true
		}
	}
	if len(responseIDs) == 1 && responseIDs[0] == "" {
		expectedResponse = true
	}
	if !expectedResponse && len(responseIDs) > 0 {
		return nil, errors.Errorf("Expecting a proper InResponseTo value, got %#v", responseIDs)
	}

	// Try getting the IdP's cert file before using it.
	if _, err := sp.GetIdPCertFile(); err != nil {
		return nil, errors.Wrap(err, "failed to get private key")
	}

	// Validate signatures

	if res.Signature != nil {
		err := validateSignedNode(res.Signature, res.ID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to validate Response + Signature")
		}
	}

	if res.Assertion != nil && res.Assertion.Signature != nil {
		err := validateSignedNode(res.Assertion.Signature, res.Assertion.ID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to validate Assertion + Signature")
		}
	}

	// Validating message.
	signatureOK := false

	if res.Signature != nil || (res.Assertion != nil && res.Assertion.Signature != nil) {
		err := sp.verifySignature(samlResponseXML)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to verify message signature")
		} else {
			signatureOK = true
		}
	}

	// Retrieve assertion
	var assertion *Assertion

	if res.EncryptedAssertion != nil {
		keyFile, err := sp.PrivkeyFile()
		if err != nil {
			return nil, errors.Errorf("Failed to get private key: %v", err)
		}

		plainTextAssertion, err := xmlsec.Decrypt(res.EncryptedAssertion.EncryptedData, keyFile)
		if err != nil {
			if IsSecurityException(err, &sp.SecurityOpts) {
				return nil, errors.Wrap(err, "Unable to decrypt message")
			}
		}

		assertion = &Assertion{}
		if err := xml.Unmarshal(plainTextAssertion, assertion); err != nil {
			return nil, errors.Wrap(err, "Unable to parse assertion")
		}

		if assertion.Signature != nil {
			err := validateSignedNode(assertion.Signature, assertion.ID)
			if err != nil {
				return nil, errors.Wrap(err, "failed to validate Assertion + Signature")
			}

			err = sp.verifySignature(plainTextAssertion)
			if err != nil {
				return nil, errors.Wrapf(err, "Unable to verify assertion signature")
			} else {
				signatureOK = true
			}
		}
	} else {
		assertion = res.Assertion
	}
	if assertion == nil {
		return nil, errors.New("Missing assertion")
	}

	// Did we receive a signature?
	if !signatureOK {
		return nil, errors.New("Unable to validate signature: node not found")
	}

	// Validate assertion.
	switch {
	case sp.IdPMetadata.EntityID == "":
		// Skip issuer validation
	case res.Issuer == nil:
		return nil, errors.New(`Assertion issuer does not match expected entity ID: missing Assertion > Issuer`)
	case assertion.Issuer.Value != sp.IdPMetadata.EntityID:
		return nil, errors.Errorf("Assertion issuer does not match expected entity ID: Expected %q, got %q", sp.IdPMetadata.EntityID, assertion.Issuer.Value)
	}

	// Validate recipient
	{
		var err error
		switch {
		case assertion.Subject == nil:
			err = errors.New(`missing Assertion > Subject`)
		case assertion.Subject.SubjectConfirmation == nil:
			err = errors.New(`missing Assertion > Subject > SubjectConfirmation`)
		case assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != sp.AcsURL:
			err = errors.Errorf("unexpected assertion recipient, expected %q, got %q", sp.AcsURL, assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
		}
		if err != nil {
			return nil, errors.Wrapf(err, "invalid assertion recipient")
		}
	}

	// Make sure we have Conditions
	if assertion.Conditions == nil {
		return nil, errors.New(`missing Assertion > Conditions`)
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
		if !validFrom.IsZero() && validFrom.After(now.Add(ClockDriftTolerance)) {
			return nil, errors.Errorf("Assertion conditions are not valid yet, got %v, current time is %v", validFrom, now)
		}
	}

	{
		validUntil := assertion.Conditions.NotOnOrAfter
		if !validUntil.IsZero() && validUntil.Before(now.Add(-ClockDriftTolerance)) {
			return nil, errors.Errorf("Assertion conditions already expired, got %v current time is %v, extra time is %v", validUntil, now, now.Add(-ClockDriftTolerance))
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

	if validUntil := assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter; validUntil.Before(now.Add(-ClockDriftTolerance)) {
		err := errors.Errorf("Assertion conditions already expired, got %v current time is %v", validUntil, now)
		return nil, errors.Wrap(err, "Assertion conditions already expired")
	}

	// if assertion.Conditions != nil && assertion.Conditions.AudienceRestriction != nil {
	//   if assertion.Conditions.AudienceRestriction.Audience.Value != sp.MetadataURL {
	//     returnt.Errorf("Audience restriction mismatch, got %q, expected %q", assertion.Conditions.AudienceRestriction.Audience.Value, sp.MetadataURL), errors.New("Audience restriction mismatch")
	//   }
	// }

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
		return nil, errors.New("Unexpected assertion InResponseTo value")
	}

	return assertion, nil
}

func validateSignedNode(signature *xmlsec.Signature, nodeID string) error {
	signatureURI := signature.Reference.URI
	if signatureURI == "" {
		return nil
	}
	if strings.HasPrefix(signatureURI, "#") {
		if nodeID == signatureURI[1:] {
			return nil
		}
		return fmt.Errorf("signed Reference.URI %q does not match ID %v", signatureURI, nodeID)
	}
	return fmt.Errorf("cannot lookup external URIs (%q)", signatureURI)
}
