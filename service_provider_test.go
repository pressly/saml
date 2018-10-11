package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

var testSP = &ServiceProvider{
	PrivkeyPEM: `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`,
	PubkeyPEM: `-----BEGIN CERTIFICATE-----
MIIFqTCCA5GgAwIBAgIJANnmNJJ15Nh+MA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNV
BAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYD
VQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5
LmNvbTAeFw0xNzA4MjYwMDA4MThaFw0yNzA4MjQwMDA4MThaMGsxCzAJBgNVBAYT
AkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQK
DAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNv
bTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPHgIgA/6mzofjwQjmFh
Y7lW8Hh1AG//efBtIRft3IlgqgQ8zmFDvBoo/kvWAUmYRDE/LQiPsjJuMF5gwRwN
5wLOpnomfeyiurFOdSBT7lSLqvtZWP35H+FpuXaT/nJ2YupYNHABb6e0veXM3JN2
KdoKsVts0RvNnfyi/aeKxnmgrnrRERR0yBdKIcsw2W4hGnB4Xp8vXG8ZNXzZZTVI
MrYUAOCVjH+BviB4wqk63K6Nu4KnrVmCEAyw9xpIeHlMGmOnHdyoSUBlicbMJl90
uxjjEzN5eAn6J3q+tzFeR/2c6BMJXVRZ2YDb/LWhKoaXK8kwzwyIQxUoXc7Soz4v
+uWSNKh9oJSy757T0KlR+cu4z3o1tpjDv/QZc6xN9yJb7/Vg4shbVneHupa51K/H
oRiXD/DEmA3daerEvcidj/Xrriui+J7sjXQ7mYu6/ISDrKSnX4R7nJ5FrQeiN/3N
ApVBGO1bqOi6dhv/GNQrAS5dmdCHjyL104kvyA/G7qdJ1iJVI1PlQEmU8kIpgxYy
rMMZWhBfM1/+6PY8r57/NJm/G7u7eFKQQ1hk1x9e7uPfTjcdbCBwSPiPvy59cCkQ
9P5NaOaYapmGoquyRnw3ZoqRDnC3PKttt47DzN5OK2mbLyaCppoubzYmZf+lG0nw
ddcd2sp0GdGHWLT0aiPaGtzzAgMBAAGjUDBOMB0GA1UdDgQWBBSjhCS8oXZKkctM
4QyAzLyFSJuaLTAfBgNVHSMEGDAWgBSjhCS8oXZKkctM4QyAzLyFSJuaLTAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQDjxydOEhvcpLM3Xoz28dlw4CsU
9qev6Lokv5K4fj7qMFi6zkjSVrzQ8C0T2WfuU8eReTXhCwUbT+Vq2X5+S3zplmRh
HmbKbclkj0C2LfQpqdqs6JGke9PsQOxkhzcIF4CDqMSrN6q60UeRPxQ8HM0tkh7E
IXp83NINHOULDJgGl9yGGpiV00r0iPDh+y6rGEZMoKw1WOUghLkmMLemd8tELXDO
Rgaofsjz14y3le7JiWkaKA6EbmJReSDrmjuqp0O2cs3bqUsHlLQ20VtrmPS1Lw6j
ABujC6NA0CxwwIY5MRRRnXjTrc31CRlBRhM9f9YpEeZuCy3k7UuK6zeP0cAY3Jtt
78SMLxzemJu4RRNqFypTwue1uBlDC+zO6Cpjh+D54laptRfFIg/bZ91zR3KOESAs
vEfVG9CShRxHocy6Q+6oy852Ry6T8blVP6/SOlvB9A++cMoO/idDQ4yGIKicM98z
cenf72Hn3I1h5BiGNM8TBkZQ1OvZ/ItrtQvMAA0x4tbHI4YU0Z8SvKsDoxmCnnby
npL/7HCzPNd56hQq0EyHGtowZmqP9bZ7geyCnAHd449vL/drGSGyvElN6QsQChvZ
zQUwDSgIrjoMPWcFNGu2pzSnQWWU7BB+DpX3jb7kHC/mLFj3M2Fxv7bCK51HWI6h
3/+aZDnC9gbMWMgwWA==
-----END CERTIFICATE-----`,

	MetadataURL:      "http://localhost:1235/saml/service.xml",
	ACSURL:           "http://localhost:1235/saml/acs",
	IdPSSOServiceURL: testIdP.SSOURL,
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
					<X509Certificate>MIIFqTCCA5GgAwIBAgIJANnmNJJ15Nh+MA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTAeFw0xNzA4MjYwMDA4MThaFw0yNzA4MjQwMDA4MThaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPHgIgA/6mzofjwQjmFhY7lW8Hh1AG//efBtIRft3IlgqgQ8zmFDvBoo/kvWAUmYRDE/LQiPsjJuMF5gwRwN5wLOpnomfeyiurFOdSBT7lSLqvtZWP35H+FpuXaT/nJ2YupYNHABb6e0veXM3JN2KdoKsVts0RvNnfyi/aeKxnmgrnrRERR0yBdKIcsw2W4hGnB4Xp8vXG8ZNXzZZTVIMrYUAOCVjH+BviB4wqk63K6Nu4KnrVmCEAyw9xpIeHlMGmOnHdyoSUBlicbMJl90uxjjEzN5eAn6J3q+tzFeR/2c6BMJXVRZ2YDb/LWhKoaXK8kwzwyIQxUoXc7Soz4v+uWSNKh9oJSy757T0KlR+cu4z3o1tpjDv/QZc6xN9yJb7/Vg4shbVneHupa51K/HoRiXD/DEmA3daerEvcidj/Xrriui+J7sjXQ7mYu6/ISDrKSnX4R7nJ5FrQeiN/3NApVBGO1bqOi6dhv/GNQrAS5dmdCHjyL104kvyA/G7qdJ1iJVI1PlQEmU8kIpgxYyrMMZWhBfM1/+6PY8r57/NJm/G7u7eFKQQ1hk1x9e7uPfTjcdbCBwSPiPvy59cCkQ9P5NaOaYapmGoquyRnw3ZoqRDnC3PKttt47DzN5OK2mbLyaCppoubzYmZf+lG0nwddcd2sp0GdGHWLT0aiPaGtzzAgMBAAGjUDBOMB0GA1UdDgQWBBSjhCS8oXZKkctM4QyAzLyFSJuaLTAfBgNVHSMEGDAWgBSjhCS8oXZKkctM4QyAzLyFSJuaLTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQDjxydOEhvcpLM3Xoz28dlw4CsU9qev6Lokv5K4fj7qMFi6zkjSVrzQ8C0T2WfuU8eReTXhCwUbT+Vq2X5+S3zplmRhHmbKbclkj0C2LfQpqdqs6JGke9PsQOxkhzcIF4CDqMSrN6q60UeRPxQ8HM0tkh7EIXp83NINHOULDJgGl9yGGpiV00r0iPDh+y6rGEZMoKw1WOUghLkmMLemd8tELXDORgaofsjz14y3le7JiWkaKA6EbmJReSDrmjuqp0O2cs3bqUsHlLQ20VtrmPS1Lw6jABujC6NA0CxwwIY5MRRRnXjTrc31CRlBRhM9f9YpEeZuCy3k7UuK6zeP0cAY3Jtt78SMLxzemJu4RRNqFypTwue1uBlDC+zO6Cpjh+D54laptRfFIg/bZ91zR3KOESAsvEfVG9CShRxHocy6Q+6oy852Ry6T8blVP6/SOlvB9A++cMoO/idDQ4yGIKicM98zcenf72Hn3I1h5BiGNM8TBkZQ1OvZ/ItrtQvMAA0x4tbHI4YU0Z8SvKsDoxmCnnbynpL/7HCzPNd56hQq0EyHGtowZmqP9bZ7geyCnAHd449vL/drGSGyvElN6QsQChvZzQUwDSgIrjoMPWcFNGu2pzSnQWWU7BB+DpX3jb7kHC/mLFj3M2Fxv7bCK51HWI6h3/+aZDnC9gbMWMgwWA==</X509Certificate>
				</X509Data>
			</KeyInfo>
		</KeyDescriptor>
		<KeyDescriptor use="encryption">
			<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
				<X509Data>
					<X509Certificate>MIIFqTCCA5GgAwIBAgIJANnmNJJ15Nh+MA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTAeFw0xNzA4MjYwMDA4MThaFw0yNzA4MjQwMDA4MThaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPHgIgA/6mzofjwQjmFhY7lW8Hh1AG//efBtIRft3IlgqgQ8zmFDvBoo/kvWAUmYRDE/LQiPsjJuMF5gwRwN5wLOpnomfeyiurFOdSBT7lSLqvtZWP35H+FpuXaT/nJ2YupYNHABb6e0veXM3JN2KdoKsVts0RvNnfyi/aeKxnmgrnrRERR0yBdKIcsw2W4hGnB4Xp8vXG8ZNXzZZTVIMrYUAOCVjH+BviB4wqk63K6Nu4KnrVmCEAyw9xpIeHlMGmOnHdyoSUBlicbMJl90uxjjEzN5eAn6J3q+tzFeR/2c6BMJXVRZ2YDb/LWhKoaXK8kwzwyIQxUoXc7Soz4v+uWSNKh9oJSy757T0KlR+cu4z3o1tpjDv/QZc6xN9yJb7/Vg4shbVneHupa51K/HoRiXD/DEmA3daerEvcidj/Xrriui+J7sjXQ7mYu6/ISDrKSnX4R7nJ5FrQeiN/3NApVBGO1bqOi6dhv/GNQrAS5dmdCHjyL104kvyA/G7qdJ1iJVI1PlQEmU8kIpgxYyrMMZWhBfM1/+6PY8r57/NJm/G7u7eFKQQ1hk1x9e7uPfTjcdbCBwSPiPvy59cCkQ9P5NaOaYapmGoquyRnw3ZoqRDnC3PKttt47DzN5OK2mbLyaCppoubzYmZf+lG0nwddcd2sp0GdGHWLT0aiPaGtzzAgMBAAGjUDBOMB0GA1UdDgQWBBSjhCS8oXZKkctM4QyAzLyFSJuaLTAfBgNVHSMEGDAWgBSjhCS8oXZKkctM4QyAzLyFSJuaLTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQDjxydOEhvcpLM3Xoz28dlw4CsU9qev6Lokv5K4fj7qMFi6zkjSVrzQ8C0T2WfuU8eReTXhCwUbT+Vq2X5+S3zplmRhHmbKbclkj0C2LfQpqdqs6JGke9PsQOxkhzcIF4CDqMSrN6q60UeRPxQ8HM0tkh7EIXp83NINHOULDJgGl9yGGpiV00r0iPDh+y6rGEZMoKw1WOUghLkmMLemd8tELXDORgaofsjz14y3le7JiWkaKA6EbmJReSDrmjuqp0O2cs3bqUsHlLQ20VtrmPS1Lw6jABujC6NA0CxwwIY5MRRRnXjTrc31CRlBRhM9f9YpEeZuCy3k7UuK6zeP0cAY3Jtt78SMLxzemJu4RRNqFypTwue1uBlDC+zO6Cpjh+D54laptRfFIg/bZ91zR3KOESAsvEfVG9CShRxHocy6Q+6oy852Ry6T8blVP6/SOlvB9A++cMoO/idDQ4yGIKicM98zcenf72Hn3I1h5BiGNM8TBkZQ1OvZ/ItrtQvMAA0x4tbHI4YU0Z8SvKsDoxmCnnbynpL/7HCzPNd56hQq0EyHGtowZmqP9bZ7geyCnAHd449vL/drGSGyvElN6QsQChvZzQUwDSgIrjoMPWcFNGu2pzSnQWWU7BB+DpX3jb7kHC/mLFj3M2Fxv7bCK51HWI6h3/+aZDnC9gbMWMgwWA==</X509Certificate>
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

	req, err := testSP.NewAuthnRequest()
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to create new AuthnRequest"))
	}

	out, err := xml.MarshalIndent(req, "", "\t")
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to marshal indent AuthnRequest"))
	}

	expectedOutput := `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-MOCKID" Version="2.0" IssueInstant="` + Now().Format(time.RFC3339Nano) + `" Destination="http://localhost:1233/saml/sso" AssertionConsumerServiceURL="http://localhost:1235/saml/acs" ProtocolBinding="">
	<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:1235/saml/service.xml</Issuer>
	<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol" AllowCreate="true">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>
</AuthnRequest>`

	if string(out) != expectedOutput {
		t.Log(diffmatchpatch.New().DiffPrettyText(diffmatchpatch.New().DiffMain(string(out), expectedOutput, true)))
		t.Fatal("unexpected output")
	}
}
