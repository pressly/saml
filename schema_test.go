package saml

import (
	"encoding/xml"
	"testing"

	"github.com/pkg/errors"
)

func TestSAMLResponse(t *testing.T) {
	tests := []struct {
		Name            string
		SAMLResponseXML string
		ResIssuer       string
		AssertionIssuer string
	}{
		{
			Name: "Test when Issuer is only present in the Assertion",
			SAMLResponseXML: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com/acs"
					ID="_e6541ed52ae03a53b79f89c9c8f15118" IssueInstant="2018-09-12T11:00:22.192Z" Version="2.0">
					<samlp:Status>
						<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
					</samlp:Status>
					<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_68313b3fa8569e77d7218d94d0685485"
						IssueInstant="2018-09-12T11:00:22.192Z" Version="2.0">
						<saml:Issuer>https://idp.example.com/metadata/idp.xml</saml:Issuer>
						<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
						</ds:Signature>
						<saml:Subject>
						</saml:Subject>
						<saml:Conditions NotBefore="2018-09-12T11:00:07.192Z" NotOnOrAfter="2018-09-12T11:03:42.192Z">
						</saml:Conditions>
						<saml:AuthnStatement AuthnInstant="2018-09-12T11:00:22.192Z" SessionIndex="_c732ada8911263dc504b45bf257e2f1b">
						</saml:AuthnStatement>
					</saml:Assertion>
				</samlp:Response>`,
			AssertionIssuer: "https://idp.example.com/metadata/idp.xml",
		},
		{
			Name: "Test when Issuer is present on both the Assertion and Response",
			SAMLResponseXML: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com/acs"
					ID="_e6541ed52ae03a53b79f89c9c8f15118" IssueInstant="2018-09-12T11:00:22.192Z" Version="2.0">
					<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/metadata/idp.xml</saml2:Issuer>
					<samlp:Status>
						<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
					</samlp:Status>
					<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_68313b3fa8569e77d7218d94d0685485"
						IssueInstant="2018-09-12T11:00:22.192Z" Version="2.0">
						<saml:Issuer>https://idp.example.com/metadata/idp.xml</saml:Issuer>
						<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
						</ds:Signature>
						<saml:Subject>
						</saml:Subject>
						<saml:Conditions NotBefore="2018-09-12T11:00:07.192Z" NotOnOrAfter="2018-09-12T11:03:42.192Z">
						</saml:Conditions>
						<saml:AuthnStatement AuthnInstant="2018-09-12T11:00:22.192Z" SessionIndex="_c732ada8911263dc504b45bf257e2f1b">
						</saml:AuthnStatement>
					</saml:Assertion>
				</samlp:Response>`,
			ResIssuer:       "https://idp.example.com/metadata/idp.xml",
			AssertionIssuer: "https://idp.example.com/metadata/idp.xml",
		},
	}

	for _, tt := range tests {
		var res Response
		if err := xml.Unmarshal([]byte(tt.SAMLResponseXML), &res); err != nil {
			t.Fatal(errors.Wrapf(err, "%v: failed to unmarshal response XML", tt.Name))
		}

		// Check for Issuer set in the Response
		if tt.ResIssuer != "" {
			if res.Issuer == nil {
				t.Fatalf("%v: failed to parse issuer", tt.Name)
			}
			if tt.ResIssuer != res.Issuer.Value {
				t.Fatalf("%v: expected issuer to be %v but got %v", tt.Name, tt.ResIssuer, res.Issuer.Value)
			}
		}

		// Check for Issuer set in the Assertion
		if tt.AssertionIssuer != "" {
			if res.Assertion == nil {
				t.Fatalf("%v: failed to parse assertion", tt.Name)
			}
			if res.Assertion.Issuer == nil {
				t.Fatalf("%v: failed to parse assertion issuer", tt.Name)
			}
			if tt.AssertionIssuer != res.Assertion.Issuer.Value {
				t.Fatalf("%v: expected assertion issuer to be %v but got %v", tt.Name, tt.AssertionIssuer, res.Assertion.Issuer)
			}
		}
	}
}
