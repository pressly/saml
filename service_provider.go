package saml

import (
	"bytes"
	"compress/flate"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/beevik/etree"
	"github.com/goware/saml/xmlsec"
	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
)

// ServiceProvider represents a service provider.
type ServiceProvider struct {
	MetadataURL string

	// Identifier of the SP entity  (must be a URI)
	EntityID string

	// Assertion Consumer Service URL
	// Specifies where the <AuthnResponse> message MUST be returned to
	ACSURL string

	// SAML protocol binding to be used when returning the <Response> message.
	// Supports only HTTP-POST binding
	ACSBinding string

	AllowIdpInitiated bool

	SecurityOpts

	// File system location of the private key file
	KeyFile string

	// File system location of the cert file
	CertFile string

	// Private key can also be provided as a param
	// For now we need to write to a temp file since xmlsec requires a physical file to validate the document signature
	PrivkeyPEM string

	// Cert can also be provided as a param
	// For now we need to write to a temp file since xmlsec requires a physical file to validate the document signature
	PubkeyPEM string

	DTDFile string

	pemCert atomic.Value

	// Identity Provider settings the Service Provider instance should use
	IdPMetadataURL string
	IdPMetadataXML []byte
	IdPMetadata    *Metadata

	// Identifier of the SP entity (must be a URI)
	IdPEntityID string

	// File system location of the cert file
	IdPCertFile string
	// Cert can also be provided as a param
	// For now we need to write to a temp file since xmlsec requires a physical file to validate the document signature
	IdPPubkeyPEM string

	// SAML protocol binding to be used when sending the <AuthnRequest> message
	IdPSSOServiceBinding string

	// URL Target of the IdP where the SP will send the AuthnRequest message
	IdPSSOServiceURL string

	IdPSignSAMLRequest bool
}

// PrivkeyFile returns a physical path where the SP's key can be accessed.
func (sp *ServiceProvider) PrivkeyFile() (string, error) {
	if sp.KeyFile != "" {
		return sp.KeyFile, nil
	}
	if sp.PrivkeyPEM != "" {
		return writeFile([]byte(sp.PrivkeyPEM))
	}
	return "", errors.New("missing sp private key")
}

// PubkeyFile returns a physical path where the SP's public certificate can be
// accessed.
func (sp *ServiceProvider) PubkeyFile() (string, error) {
	if sp.CertFile != "" {
		return validateKeyFile(sp.CertFile, nil)
	}
	if sp.PubkeyPEM != "" {
		return validateKeyFile(writeFile([]byte(sp.PubkeyPEM)))
	}
	return "", errors.New("missing sp public key")
}

// GetIdPCertFile returns a physical path where the IdP certificate can be
// accessed.
func (sp *ServiceProvider) GetIdPCertFile() (string, error) {
	if sp.IdPPubkeyPEM == "" {
		return "", errors.New("missing idp certificate")
	}

	certBytes, _ := base64.StdEncoding.DecodeString(sp.IdPPubkeyPEM)

	certBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return writeFile(certBytes)
}

func (sp *ServiceProvider) ParseIdPMetadata() (*Metadata, error) {
	var metadata *Metadata
	switch {
	case len(sp.IdPMetadataXML) > 0:
		if err := xml.Unmarshal(sp.IdPMetadataXML, &metadata); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal metadata: %v", string(sp.IdPMetadataXML))
		}
	case sp.IdPMetadataURL != "":
		res, err := http.Get(sp.IdPMetadataURL)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get %q", sp.IdPMetadataURL)
		}
		defer res.Body.Close()

		buf, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read body from %q", sp.IdPMetadataURL)
		}
		if err := xml.Unmarshal(buf, &metadata); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal body: %+v", string(buf))
		}
	}

	if metadata == nil {
		return nil, errors.Errorf("missing idp metadata xml/url")
	}

	return metadata, nil
}

// Cert returns a *pem.Block value that corresponds to the SP's certificate.
func (sp *ServiceProvider) Cert() (*pem.Block, error) {
	if v := sp.pemCert.Load(); v != nil {
		return v.(*pem.Block), nil
	}

	certFile, err := sp.PubkeyFile()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get sp cert key file")
	}

	fp, err := os.Open(certFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open sp cert file: %v", certFile)
	}
	defer fp.Close()

	buf, err := ioutil.ReadAll(fp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read sp cert file")
	}

	cert, _ := pem.Decode(buf)
	if cert == nil {
		return nil, errors.New("invalid sp certificate")
	}

	sp.pemCert.Store(cert)

	return cert, nil
}

// Metadata returns a metadata value based on the SP's data.
func (sp *ServiceProvider) Metadata() (*Metadata, error) {
	cert, err := sp.Cert()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get sp cert")
	}
	certStr := base64.StdEncoding.EncodeToString(cert.Bytes)

	metadata := &Metadata{
		EntityID:   sp.MetadataURL,
		ValidUntil: Now().Add(defaultValidDuration),
		SPSSODescriptor: &SPSSODescriptor{
			AuthnRequestsSigned:        false,
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: []KeyDescriptor{
				KeyDescriptor{
					Use: "signing",
					KeyInfo: KeyInfo{
						Certificate: certStr,
					},
				},
				KeyDescriptor{
					Use: "encryption",
					KeyInfo: KeyInfo{
						Certificate: certStr,
					},
					EncryptionMethods: []EncryptionMethod{
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
					},
				},
			},
			AssertionConsumerService: []IndexedEndpoint{{
				Binding:  HTTPPostBinding,
				Location: sp.ACSURL,
				Index:    1,
			}},
		},
	}

	return metadata, nil
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

// NewAuthnRequest creates a new AuthnRequest object for the given IdP URL.
func (sp *ServiceProvider) SAMLRequest(relayState string) (string, error) {
	authnRequest, err := sp.NewAuthnRequest()
	if err != nil {
		return "", errors.Wrap(err, "failed to create auth request")
	}

	buf, err := xml.MarshalIndent(authnRequest, "", "\t")
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal auth request")
	}

	switch sp.IdPSSOServiceBinding {
	case HTTPRedirectBinding:
		return sp.SAMLRequestURL(buf, relayState)

	case HTTPPostBinding:
		return sp.SAMLRequestForm(buf, relayState)

	default:
		// default to HTTP-Redirect?
		return "", errors.Errorf("invalid sso service binding")
	}
}

// AuthnRequestURL creates SAML 2.0 AuthnRequest redirect URL,
// aka SP-initiated login (SP->IdP).
// The data is passed in the ?SAMLRequest query parameter and
// the value is base64 encoded and deflate-compressed <AuthnRequest>
// XML element. The final redirect destination that will be invoked
// on successful login is passed using ?RelayState query parameter.
//
// NewSAMLRequest creates SAML 2.0 AuthnRequest
// The <AuthnRequest> XML element is deflate-compressed, base64 and URL encoded
// TODO(diogo): HTTP-Redirect signed requests
func (sp *ServiceProvider) SAMLRequestURL(authnRequest []byte, relayState string) (string, error) {
	// Compress authnRequest
	flateBuf := bytes.NewBuffer(nil)
	flateWriter, err := flate.NewWriter(flateBuf, flate.DefaultCompression)
	if err != nil {
		return "", errors.Wrap(err, "failed to create flate writer")
	}
	if _, err = flateWriter.Write(authnRequest); err != nil {
		return "", errors.Wrap(err, "failed to write to flate writer")
	}
	flateWriter.Close()
	authnReqCompressedBytes := flateBuf.Bytes()

	// Base64 encode authnRequest
	authnReqBase64Encoded := base64.StdEncoding.EncodeToString(authnReqCompressedBytes)

	// Escape authnRequest
	authnReqEscaped := url.QueryEscape(authnReqBase64Encoded)

	// Escape relay state
	relayStateEscaped := url.QueryEscape(relayState)

	return fmt.Sprintf(`%s?RelayState=%s&SAMLRequest=%s`, sp.IdPSSOServiceURL, relayStateEscaped, authnReqEscaped), nil
}

// NewSAMLRequest creates SAML 2.0 AuthnRequest
// The <AuthnRequest> XML element is base64 encoded
func (sp *ServiceProvider) SAMLRequestForm(authnRequest []byte, relayState string) (string, error) {
	if sp.IdPSignSAMLRequest {
		pubkeyFile, err := sp.PubkeyFile()
		if err != nil {
			return "", errors.Wrap(err, "failed to read service provider public key")
		}
		privkeyFile, err := sp.PrivkeyFile()
		if err != nil {
			return "", errors.Wrap(err, "failed to read service provider private key")
		}

		cert, err := tls.LoadX509KeyPair(pubkeyFile, privkeyFile)
		if err != nil {
			return "", errors.Wrap(err, "failed to load service provider key pair")
		}

		signingContext := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(cert))
		// TODO: review
		// signingContext.SetSignatureMethod(sp.SignAuthnRequestsAlgorithm)

		doc := etree.NewDocument()
		err = doc.ReadFromBytes(authnRequest)
		if err != nil {
			return "", errors.Wrap(err, "failed to deserialize authn request into xml document")
		}

		// TODO: bounds check
		// Review the signing flow
		el := doc.Child[0].(*etree.Element)
		sig, err := signingContext.ConstructSignature(el, true)
		if err != nil {
			return "", errors.Wrap(err, "failed to build authn request signature")
		}

		elCopy := el.Copy()
		// TODO: review how the final AuthnRequest is built
		// Right now it is following the flow defined in the gosaml2 lib: https://github.com/russellhaering/gosaml2/blob/master/build_request.go#L17
		var children []etree.Token
		children = append(children, elCopy.Child[1])     // issuer is always first
		children = append(children, sig)                 // next is the signature
		children = append(children, elCopy.Child[2:]...) // then all other children
		elCopy.Child = children

		doc = etree.NewDocument()
		doc.SetRoot(elCopy)
		if authnRequest, err = doc.WriteToBytes(); err != nil {
			return "", errors.Wrap(err, "failed to write xml document to string")
		}
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
`, sp.IdPSSOServiceURL, relayState, base64.StdEncoding.EncodeToString(authnRequest))

	return payload, nil
}

// NewAuthnRequest creates a new AuthnRequest object for the given IdP URL.
func (sp *ServiceProvider) NewAuthnRequest() (*AuthnRequest, error) {
	// TODO: validate?

	req := AuthnRequest{
		AssertionConsumerServiceURL: sp.ACSURL,
		Destination:                 sp.IdPSSOServiceURL,
		ID:                          NewID(),
		IssueInstant:                Now(),
		Version:                     "2.0",
		ProtocolBinding:             sp.IdPSSOServiceBinding,
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  sp.MetadataURL,
		},
		NameIDPolicy: NameIDPolicy{
			AllowCreate: true,
			// TODO(ross): figure out exactly policy we need
			// urn:mace:shibboleth:1.0:nameIdentifier
			// urn:oasis:names:tc:SAML:2.0:nameid-format:transient
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
	}
	return &req, nil
}

// AssertResponse parses and validates a SAML response and its assertion
func (sp *ServiceProvider) AssertResponse(base64Res string) (*Assertion, error) {
	// Parse SAML response from base64 encoded payload
	//
	samlResponseXML, err := base64.StdEncoding.DecodeString(base64Res)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to base64-decode SAML response")
	}
	var res *Response
	if err := xml.Unmarshal(samlResponseXML, &res); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal XML document: %s", string(samlResponseXML))
	}

	// Validate response
	//
	// Validate destination
	// Note: OneLogin triggers this error when the Recipient field
	// is left blank (or when not set to the correct ACS endpoint)
	// in the OneLogin SAML configuration page. OneLogin returns
	// Destination="{recipient}" in the SAML reponse in this case.
	if res.Destination != sp.ACSURL {
		return nil, errors.Errorf("Wrong ACS destination, expected %q, got %q", sp.ACSURL, res.Destination)
	}
	if res.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return nil, errors.Errorf("Unexpected status code: %v", res.Status.StatusCode.Value)
	}

	// Validates if the assertion matches the ID set in the original SAML AuthnRequest
	//
	// This check should be performed first before validating the signature since it is a cheap way to discard invalid messages
	// TODO: Track request IDs and add option to set them back in the service provider
	// This code will always pass since the possible response IDs is hardcoded to have a single empty string element
	// expectedResponse := false
	// responseIDs := sp.possibleResponseIDs()
	// for i := range responseIDs {
	// 	if responseIDs[i] == assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo {
	// 		expectedResponse = true
	// 	}
	// }
	// if len(responseIDs) == 1 && responseIDs[0] == "" {
	// 	expectedResponse = true
	// }

	// if !expectedResponse && len(responseIDs) > 0 {
	// 	return nil, errors.New("Unexpected assertion InResponseTo value")
	// }

	// Save XML raw bytes so later we can reuse it to verify the signature
	plainText := samlResponseXML

	// Validate response reference
	// Before validating the signature with xmlsec, first check if the reference ID is correct
	//
	// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 5.3
	if res.Signature != nil {
		if err := verifySignatureReference(res.Signature, res.ID); err != nil {
			return nil, errors.Wrap(err, "failed to validate response signature reference")
		}
		if err := sp.verifySignature(plainText); err != nil {
			return nil, errors.Wrapf(err, "failed to verify message signature: %v", string(plainText))
		}
	}

	// Check for encrypted assertions
	// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 2.3.4
	assertion := res.Assertion
	if res.EncryptedAssertion != nil {
		keyFile, err := sp.PrivkeyFile()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get private key file")
		}

		plainTextAssertion, err := xmlsec.Decrypt(res.EncryptedAssertion.EncryptedData, keyFile)
		if err != nil {
			if IsSecurityException(err, &sp.SecurityOpts) {
				return nil, errors.Wrap(err, "failed to decrypt assertion")
			}
		}

		assertion = &Assertion{}
		if err := xml.Unmarshal(plainTextAssertion, assertion); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal encrypted assertion: %v", plainTextAssertion)
		}

		// Track plain text so later we can verify the signature with xmlsec
		plainText = plainTextAssertion
	}

	if assertion == nil {
		return nil, errors.New("missing assertion element")
	}

	// Validate assertion reference
	// Before validating the signature with xmlsec, first check if the reference ID is correct
	//
	// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 5.3
	if assertion.Signature != nil {
		if err := verifySignatureReference(assertion.Signature, assertion.ID); err != nil {
			return nil, errors.Wrap(err, "failed to validate assertion signature reference")
		}
		if err := sp.verifySignature(plainText); err != nil {
			return nil, errors.Wrapf(err, "failed to verify message signature: %v", string(plainText))
		}
	}

	// Validate issuer
	// Since assertion could be encrypted we need to wait before validating the issuer
	// Only validate issuer if the entityID is set in the IdP metadata
	// TODO: the spec lists the Issuer element of an Assertion as required, we shouldn't skip validation
	switch {
	case sp.IdPEntityID == "":
		// Skip issuer validationgit s
	case assertion.Issuer == nil:
		return nil, errors.New(`missing Assertion > Issuer`)
	case assertion.Issuer.Value != sp.IdPEntityID:
		return nil, errors.Errorf("failed to validate assertion issuer: expected %q but got %q", sp.IdPEntityID, assertion.Issuer.Value)
	}

	// Validate recipient
	switch {
	case assertion.Subject == nil:
		err = errors.New(`missing Assertion > Subject`)
	case assertion.Subject.SubjectConfirmation == nil:
		err = errors.New(`missing Assertion > Subject > SubjectConfirmation`)
	case assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != sp.ACSURL:
		err = errors.Errorf("failed to validate assertion recipient: expected %q but got %q", sp.ACSURL, assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "invalid assertion recipient")
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
	now := Now()
	validFrom := assertion.Conditions.NotBefore
	if !validFrom.IsZero() && validFrom.After(now.Add(ClockDriftTolerance)) {
		return nil, errors.Errorf("Assertion conditions are not valid yet, got %v, current time is %v", validFrom, now)
	}
	validUntil := assertion.Conditions.NotOnOrAfter
	if !validUntil.IsZero() && validUntil.Before(now.Add(-ClockDriftTolerance)) {
		return nil, errors.Errorf("Assertion conditions already expired, got %v current time is %v, extra time is %v", validUntil, now, now.Add(-ClockDriftTolerance))
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

	// TODO: reenable?
	// if assertion.Conditions != nil && assertion.Conditions.AudienceRestriction != nil {
	//   if assertion.Conditions.AudienceRestriction.Audience.Value != sp.MetadataURL {
	//     returnt.Errorf("Audience restriction mismatch, got %q, expected %q", assertion.Conditions.AudienceRestriction.Audience.Value, sp.MetadataURL), errors.New("Audience restriction mismatch")
	//   }
	// }

	return assertion, nil
}

func (sp *ServiceProvider) verifySignature(plaintextMessage []byte) error {
	idpCertFile, err := sp.GetIdPCertFile()
	if err != nil {
		return errors.Wrap(err, "failed to get idp cert file")
	}

	if err := xmlsec.Verify(plaintextMessage, idpCertFile, &xmlsec.ValidationOptions{
		DTDFile: sp.DTDFile,
	}); err != nil {
		if !IsSecurityException(err, &sp.SecurityOpts) {
			// ...but it was not a security exception, so we ignore it and accept
			// the verification.
			return nil
		}
		return errors.Wrap(err, "failed to verify xmlsec signature")
	}
	return nil
}

// Check if signature reference URI matches root element ID
// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 5.4.2
func verifySignatureReference(signature *xmlsec.Signature, nodeID string) error {
	signatureURI := signature.Reference.URI
	if signatureURI == "" {
		return nil
	}
	if strings.HasPrefix(signatureURI, "#") {
		if nodeID == signatureURI[1:] {
			return nil
		}
		return errors.Errorf("signature Reference.URI %q does not match ID %v", signatureURI, nodeID)
	}
	return errors.Errorf("cannot lookup external URIs (%q)", signatureURI)
}

func (sp *ServiceProvider) possibleResponseIDs() []string {
	responseIDs := []string{}
	if sp.AllowIdpInitiated {
		responseIDs = append(responseIDs, "")
	}
	return responseIDs
}
