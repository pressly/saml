package saml

import (
	"encoding/xml"
	"testing"
	"time"
	//"log"

	"github.com/stretchr/testify/assert"
)

var testSP = &ServiceProvider{
	PrivkeyPEM: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdhsh0bElTmZuK
pbNI41b1vXk6HT3V5DFlftyHUhW253wAtVgYg24ytdyuZJud9Ajqlz3aCnMfUCea
N6mEjQ9x+6SGeyfv4hg/PGCYx53bkTLBVfYbVh1/S+izGc43JvCqiaU1UX0GcZvh
3iphy/H5PPbSr+HuZRsCdF61rRnuMJAGW2EVlAywN82KMfubufjL5EzYO8UQGQSw
YgPWj2eAm4/RtLAafBU7gClBcn50R2/2ss1IDJvWB3VQ+7S8e0mkdUaosExDAUZL
QG+AIReU9zhwSOWc72hSKSRTBX3M7BZEVQHG/FmSkh60C3r0TsFprD/Nnj460JIG
T3DeA0/lAgMBAAECggEAXIB5l9PX0qbjwkNq19bGaxrRUij/tx7wWXdd0su98YA7
0Xfn72SCUX6LRe8Q5CYQyxSYaUHPzJWF0+nGSWk1t9ziWJ14kbyRb2Zg16sTCapZ
zU191PBipNMnuhHegD0sZanQaLE8ScKK2wgQHoIw6mhAkL2M1CU34BCDs80ydLjf
a4viX6PKTbgb8zJxMEPKW83y2LBdTOA5F7ao9jnhc9RZd68qxeGRD4FGnQXsY4MA
uYM+mJh/E/DRIZRtEKysyHSHholzJqjLDcuxPNFc39QB1ndoEIUSr6x8ysdBdtdx
1F7bMyK9ZW7dYOHitWyFAE8yVNXk576PtbAgMpXViQKBgQD6LtZKeWMr0KefgUVy
rSnPCcFX2KU/53WW212bVvbSZQYxl72Vi2LisY8ksuEO+DUlrbjVrDdba3aWRd8z
BhaZLc/+PPC5hfigW6/ASTTXcJUzGS2+SE5cmwE+MUSmfelPRHqB3H8MdrbxKzSw
U69ZaIPlOrbyKLUurbA6SkzIxwKBgQDirV/NJJlodur/gt4pmeTpHxAhG+vahJSh
Vusk7kEBywXa8U+YPRLPCFHpk0JWfocvGHagZ+xN+flaWl5IYHHsATanmqS/NaJ/
cfZcLXzbpKCRv93k7opNeMlf/iFXcrMk4nkyRbK2H21deGG2VZFoXvbmJTCVhuoY
E34PsTxt8wKBgQCtgYwWTEct3OBTa6jJVjSXpJFVJie8wP45KFur3s0ArxVzkWPm
8asbwr6eWfxhkFvzjJ6SeYROv6GXqE+aKE/F3hLQpFzinXoHZG7n8R1XiHnA3WZu
/+BwswNSqYKN4ObMlZZMt6nY8AACE8/Ptcn3PNe0Q1sbaIX3IHgGhP7pgwKBgD1O
gNOd63PKfeJfRbDgs32tbhJWV+LA6uX7+RsC6UgP3eSKUWmuUvD1ohnXPyDflbZS
GntlwA6S5jLesBNJKmaXKW4JMDeazPlFHElv8A4Dp33j86KgNX2ghm5U8DWTiwoV
youjOCNzuoOGNH85A1vEG2jBdDNsytF6LCUYXWyrAoGAaxoaBF1A+dunoFBcVz3+
0w6QeqMKseGNpEtCoceZG/DFu7zajJrzcq4luMOLilJmfld5gOf8LhgZoQng6iCu
mBlhJURG4Gfy82rfW8HY47QvzsE3CHuOCsswtA+R8BKOCZRnoeyw1ypolzu5KOMJ
x56GxeyF9Zs/w00BavP0Crg=
-----END PRIVATE KEY-----`,
	PubkeyPEM: `-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIJAODc7bOlmC1fMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNV
BAMMFW15c2VydmljZS5leGFtcGxlLmNvbTAeFw0xNjA1MjAxNDEyMThaFw0xNzA1
MjAxNDEyMThaMCAxHjAcBgNVBAMMFW15c2VydmljZS5leGFtcGxlLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXJX7Clp0krx3fye0bJpu57nO+0
S7K4ycpoQBa1/bRDH8UYHnYjI679y/bpNCI768eFAusO/xBBlaE4wx9jw3Z9Cyvc
Mv+Exoo6DzLkpVvPppbZ7b+P5KR5lNRGOBdVcD9DIQ0Iyhpyqd92z/bZVDIc8yPI
bA3bTlJ+Na+a/XpqOP9Dma/dknobh8zY9Z82xLGaFEbuRZ0K9HTV1riOycTgsXZq
o9lk2p1CZbcsjrk1t6t1NuzVXyy1rTX2rZkdJZby0m8bP8up/MRDFmMSw+iVZCby
KuzVBEGLKEN8OGFLlnmtQ75jttf/cG72lqLq0WV30kfRaESW+d1hFbtP6F0CAwEA
AaNQME4wHQYDVR0OBBYEFIa0KJ+xcDtMxasi44XONmWrOPYSMB8GA1UdIwQYMBaA
FIa0KJ+xcDtMxasi44XONmWrOPYSMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAEXDBtVBJj94e0Ly9GEa7z8zkuuWuyb49DTW9C3SGumr7fR/zJjzRP3K
qTPtEejwXHOW4iO9iCeEnTxP7xIziX9IcDX0pVUI4nNxR6YdJ9syP29Oge4TMvGF
V51HZPyDjJKWL5dpd8wBwP2VO4LfA/7uaJxftagCGjvdUGBO4hp46un3Tjmk+Pg5
4j9Su9VDd17HgeCGWzj9uVkpnlWetvubiKtazZTu1unXJQhN7RGnu7pXArW0rcIy
PDQFHpnWPAsun5ygsn8ZA9BRAzW5KSiugeg4IvtzRgQFcJj/HpYeQw8/IKrq/yk8
q4G6as+AKykV0VOmiMfigewmJRgrT1I=
-----END CERTIFICATE-----`,

	MetadataURL: "http://localhost:1235/saml/service.xml",
	AcsURL:      "http://localhost:1235/saml/acs",
}

func TestGenerateSPMetadata(t *testing.T) {
	tearUp()

	metadata, err := testSP.Metadata()

	assert.NoError(t, err)
	assert.NotNil(t, metadata)

	out, err := xml.MarshalIndent(metadata, "", "\t")
	assert.NoError(t, err)

	expectedOutput := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="` + Now().Add(defaultValidDuration).Format(time.RFC3339Nano) + `" entityID="http://localhost:1235/saml/service.xml">
	<SPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<KeyDescriptor use="signing">
			<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
				<X509Data>
					<X509Certificate>MIIDEzCCAfugAwIBAgIJAODc7bOlmC1fMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMMFW15c2VydmljZS5leGFtcGxlLmNvbTAeFw0xNjA1MjAxNDEyMThaFw0xNzA1MjAxNDEyMThaMCAxHjAcBgNVBAMMFW15c2VydmljZS5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXJX7Clp0krx3fye0bJpu57nO+0S7K4ycpoQBa1/bRDH8UYHnYjI679y/bpNCI768eFAusO/xBBlaE4wx9jw3Z9CyvcMv+Exoo6DzLkpVvPppbZ7b+P5KR5lNRGOBdVcD9DIQ0Iyhpyqd92z/bZVDIc8yPIbA3bTlJ+Na+a/XpqOP9Dma/dknobh8zY9Z82xLGaFEbuRZ0K9HTV1riOycTgsXZqo9lk2p1CZbcsjrk1t6t1NuzVXyy1rTX2rZkdJZby0m8bP8up/MRDFmMSw+iVZCbyKuzVBEGLKEN8OGFLlnmtQ75jttf/cG72lqLq0WV30kfRaESW+d1hFbtP6F0CAwEAAaNQME4wHQYDVR0OBBYEFIa0KJ+xcDtMxasi44XONmWrOPYSMB8GA1UdIwQYMBaAFIa0KJ+xcDtMxasi44XONmWrOPYSMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEXDBtVBJj94e0Ly9GEa7z8zkuuWuyb49DTW9C3SGumr7fR/zJjzRP3KqTPtEejwXHOW4iO9iCeEnTxP7xIziX9IcDX0pVUI4nNxR6YdJ9syP29Oge4TMvGFV51HZPyDjJKWL5dpd8wBwP2VO4LfA/7uaJxftagCGjvdUGBO4hp46un3Tjmk+Pg54j9Su9VDd17HgeCGWzj9uVkpnlWetvubiKtazZTu1unXJQhN7RGnu7pXArW0rcIyPDQFHpnWPAsun5ygsn8ZA9BRAzW5KSiugeg4IvtzRgQFcJj/HpYeQw8/IKrq/yk8q4G6as+AKykV0VOmiMfigewmJRgrT1I=</X509Certificate>
				</X509Data>
			</KeyInfo>
		</KeyDescriptor>
		<KeyDescriptor use="encryption">
			<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
				<X509Data>
					<X509Certificate>MIIDEzCCAfugAwIBAgIJAODc7bOlmC1fMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMMFW15c2VydmljZS5leGFtcGxlLmNvbTAeFw0xNjA1MjAxNDEyMThaFw0xNzA1MjAxNDEyMThaMCAxHjAcBgNVBAMMFW15c2VydmljZS5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXJX7Clp0krx3fye0bJpu57nO+0S7K4ycpoQBa1/bRDH8UYHnYjI679y/bpNCI768eFAusO/xBBlaE4wx9jw3Z9CyvcMv+Exoo6DzLkpVvPppbZ7b+P5KR5lNRGOBdVcD9DIQ0Iyhpyqd92z/bZVDIc8yPIbA3bTlJ+Na+a/XpqOP9Dma/dknobh8zY9Z82xLGaFEbuRZ0K9HTV1riOycTgsXZqo9lk2p1CZbcsjrk1t6t1NuzVXyy1rTX2rZkdJZby0m8bP8up/MRDFmMSw+iVZCbyKuzVBEGLKEN8OGFLlnmtQ75jttf/cG72lqLq0WV30kfRaESW+d1hFbtP6F0CAwEAAaNQME4wHQYDVR0OBBYEFIa0KJ+xcDtMxasi44XONmWrOPYSMB8GA1UdIwQYMBaAFIa0KJ+xcDtMxasi44XONmWrOPYSMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEXDBtVBJj94e0Ly9GEa7z8zkuuWuyb49DTW9C3SGumr7fR/zJjzRP3KqTPtEejwXHOW4iO9iCeEnTxP7xIziX9IcDX0pVUI4nNxR6YdJ9syP29Oge4TMvGFV51HZPyDjJKWL5dpd8wBwP2VO4LfA/7uaJxftagCGjvdUGBO4hp46un3Tjmk+Pg54j9Su9VDd17HgeCGWzj9uVkpnlWetvubiKtazZTu1unXJQhN7RGnu7pXArW0rcIyPDQFHpnWPAsun5ygsn8ZA9BRAzW5KSiugeg4IvtzRgQFcJj/HpYeQw8/IKrq/yk8q4G6as+AKykV0VOmiMfigewmJRgrT1I=</X509Certificate>
				</X509Data>
			</KeyInfo>
			<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>
			<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc"></EncryptionMethod>
			<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"></EncryptionMethod>
			<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"></EncryptionMethod>
		</KeyDescriptor>
		<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:1235/saml/acs" index="1"></AssertionConsumerService>
	</SPSSODescriptor>
</EntityDescriptor>`

	assert.Equal(t, expectedOutput, string(out))
}

func TestMakeAuthenticationRequest(t *testing.T) {
	tearUp()

	req, err := testSP.MakeAuthenticationRequest(testIdP.SSOURL)
	assert.NoError(t, err)

	out, err := xml.MarshalIndent(req, "", "\t")
	assert.NoError(t, err)

	expectedOutput := `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="http://localhost:1235/saml/acs" Destination="http://localhost:1233/saml/sso" ID="id-MOCKID" IssueInstant="` + Now().Format(time.RFC3339Nano) + `" ProtocolBinding="" Version="2.0">
	<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:1235/saml/service.xml</Issuer>
	<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol" AllowCreate="true">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>
</AuthnRequest>`

	assert.Equal(t, expectedOutput, string(out))
}
