package saml

import (
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/pkg/errors"
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

// NewAuthnRequest creates a new AuthnRequest object for the given IdP URL.
func (sp *ServiceProvider) NewAuthnRequest() (*AuthnRequest, error) {
	req := AuthnRequest{
		AssertionConsumerServiceURL: sp.ACSURL,
		Destination:                 sp.IdPSSOServiceURL,
		ID:                          NewID(),
		IssueInstant:                Now(),
		Version:                     "2.0",
		ProtocolBinding:             HTTPPostBinding,
		Issuer: Issuer{
			Format: NameIDEntityFormat,
			Value:  sp.MetadataURL,
		},
		NameIDPolicy: NameIDPolicy{
			AllowCreate: true,
			Format:      NameIDEmailAddressFormat,
		},
	}

	req.XMLNamespace = ProtocolNamespace
	req.XMLName.Local = "samlp:AuthnRequest"

	req.NameIDPolicy.XMLName.Local = "samlp:NameIDPolicy"

	return &req, nil
}
