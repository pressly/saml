package saml

import (
	"encoding/xml"
	"testing"

	"github.com/pkg/errors"
)

func TestSAMLResponse(t *testing.T) {
	tests := []struct {
		Name        string
		ResponseXML string
		Issuer      string
	}{
		{
			Name: "Test 1",
			ResponseXML: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com/acs"
					ID="_e6541ed52ae03a53b79f89c9c8f15118" IssueInstant="2018-09-12T11:00:22.192Z" Version="2.0">
					<samlp:Status>
						<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
					</samlp:Status>
					<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_68313b3fa8569e77d7218d94d0685485"
						IssueInstant="2018-09-12T11:00:22.192Z" Version="2.0">
						<saml:Issuer>https://idp.example.com/metadata/idp.xml</saml:Issuer>
						<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
							<ds:SignedInfo>
								<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
								<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
								<ds:Reference URI="#_68313b3fa8569e77d7218d94d0685485">
									<ds:Transforms>
										<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
										<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
									</ds:Transforms>
									<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
									<ds:DigestValue>gkJCQk8U2luZ2xlU2lnbk9uU2VydmljZSBCaW5kc=</ds:DigestValue>
								</ds:Reference>
							</ds:SignedInfo>
							<ds:SignatureValue> kJCQl0LkZhdGFsKGVycm9ycy5XcmFwZihlcnIsICIld
							jogZmFpbGVkIHRvIHBhcnNlIGR1cmF0aW9uICgldikiLCB0dC5OYW1lLCB0dC5E
							dXJhdGlvbikpCgkJCX0KCQkJaWYgY2FjaGVEdXJhdGlvbi5EdXJhdGlvbigpICE
							9IGQgewoJCQkJdC5GYXRhbGYoIiV2OiBleHBlY3RlZCBkdXJhdGlvbiB0byBiZS
							AoJXYpIGJ1dCBnb3QgKCV2KSIsIHR0Lk5hbWUsIGQsIGNhY2hlRHVyYXRpb24uR
							HVyYXRpb24oKSkKCQkJfQoJCX0KCX0KfQo= </ds:SignatureValue>
						</ds:Signature>
						<saml:Subject>
							<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="https://idp.example.com/metadata/idp.xml">jamwald</saml:NameID>
							<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
								<saml:SubjectConfirmationData NotOnOrAfter="2018-09-12T11:03:42.192Z" Recipient="https://sp.example.com/acs" />
							</saml:SubjectConfirmation>
						</saml:Subject>
						<saml:Conditions NotBefore="2018-09-12T11:00:07.192Z" NotOnOrAfter="2018-09-12T11:03:42.192Z">
							<saml:AudienceRestriction>
								<saml:Audience>https://sp.example.com/metadata.xml</saml:Audience>
							</saml:AudienceRestriction>
						</saml:Conditions>
						<saml:AuthnStatement AuthnInstant="2018-09-12T11:00:22.192Z" SessionIndex="_c732ada8911263dc504b45bf257e2f1b">
							<saml:AuthnContext>
								<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
							</saml:AuthnContext>
						</saml:AuthnStatement>
					</saml:Assertion>
				</samlp:Response>`,
			Issuer: "https://idp.example.com/metadata/idp.xml",
		},
	}

	for _, tt := range tests {
		var res Response
		if err := xml.Unmarshal([]byte(tt.ResponseXML), &res); err != nil {
			t.Fatal(errors.Wrapf(err, "%v: failed to unmarshal response XML", tt.Name))
		}
		if res.Assertion == nil {
			t.Fatalf("%v: failed to parse assertion", tt.Name)
		}
		if res.Assertion.Issuer == nil {
			t.Fatalf("%v: failed to parse assertion issuer", tt.Name)
		}
		if tt.Issuer != res.Assertion.Issuer.Value {
			t.Fatalf("%v: expected issuer to be %v but got %v", tt.Name, tt.Issuer, res.Assertion.Issuer)
		}
	}
}
