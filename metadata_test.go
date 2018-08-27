package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/pkg/errors"
)

func TestMetadataXML(t *testing.T) {
	tests := []struct {
		Name        string
		MetadataXML string
	}{
		{
			Name: "Test 1",
			MetadataXML: `<?xml version="1.0" encoding="UTF-8"?>
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" cacheDuration="P0Y0M30DT0H0M0.000S" entityID="https://example.com/idp.xml"
				validUntil="2025-03-04T03:18:03.000Z">
				<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<md:KeyDescriptor use="signing">
						<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
							<ds:X509Data>
								<X509Certificate>MIIFqTCCA5GgAwIBAgIJANnmNJJ15Nh+MA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTAeFw0xNzA4MjYwMDA4MThaFw0yNzA4MjQwMDA4MThaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPHgIgA/6mzofjwQjmFhY7lW8Hh1AG//efBtIRft3IlgqgQ8zmFDvBoo/kvWAUmYRDE/LQiPsjJuMF5gwRwN5wLOpnomfeyiurFOdSBT7lSLqvtZWP35H+FpuXaT/nJ2YupYNHABb6e0veXM3JN2KdoKsVts0RvNnfyi/aeKxnmgrnrRERR0yBdKIcsw2W4hGnB4Xp8vXG8ZNXzZZTVIMrYUAOCVjH+BviB4wqk63K6Nu4KnrVmCEAyw9xpIeHlMGmOnHdyoSUBlicbMJl90uxjjEzN5eAn6J3q+tzFeR/2c6BMJXVRZ2YDb/LWhKoaXK8kwzwyIQxUoXc7Soz4v+uWSNKh9oJSy757T0KlR+cu4z3o1tpjDv/QZc6xN9yJb7/Vg4shbVneHupa51K/HoRiXD/DEmA3daerEvcidj/Xrriui+J7sjXQ7mYu6/ISDrKSnX4R7nJ5FrQeiN/3NApVBGO1bqOi6dhv/GNQrAS5dmdCHjyL104kvyA/G7qdJ1iJVI1PlQEmU8kIpgxYyrMMZWhBfM1/+6PY8r57/NJm/G7u7eFKQQ1hk1x9e7uPfTjcdbCBwSPiPvy59cCkQ9P5NaOaYapmGoquyRnw3ZoqRDnC3PKttt47DzN5OK2mbLyaCppoubzYmZf+lG0nwddcd2sp0GdGHWLT0aiPaGtzzAgMBAAGjUDBOMB0GA1UdDgQWBBSjhCS8oXZKkctM4QyAzLyFSJuaLTAfBgNVHSMEGDAWgBSjhCS8oXZKkctM4QyAzLyFSJuaLTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQDjxydOEhvcpLM3Xoz28dlw4CsU9qev6Lokv5K4fj7qMFi6zkjSVrzQ8C0T2WfuU8eReTXhCwUbT+Vq2X5+S3zplmRhHmbKbclkj0C2LfQpqdqs6JGke9PsQOxkhzcIF4CDqMSrN6q60UeRPxQ8HM0tkh7EIXp83NINHOULDJgGl9yGGpiV00r0iPDh+y6rGEZMoKw1WOUghLkmMLemd8tELXDORgaofsjz14y3le7JiWkaKA6EbmJReSDrmjuqp0O2cs3bqUsHlLQ20VtrmPS1Lw6jABujC6NA0CxwwIY5MRRRnXjTrc31CRlBRhM9f9YpEeZuCy3k7UuK6zeP0cAY3Jtt78SMLxzemJu4RRNqFypTwue1uBlDC+zO6Cpjh+D54laptRfFIg/bZ91zR3KOESAsvEfVG9CShRxHocy6Q+6oy852Ry6T8blVP6/SOlvB9A++cMoO/idDQ4yGIKicM98zcenf72Hn3I1h5BiGNM8TBkZQ1OvZ/ItrtQvMAA0x4tbHI4YU0Z8SvKsDoxmCnnbynpL/7HCzPNd56hQq0EyHGtowZmqP9bZ7geyCnAHd449vL/drGSGyvElN6QsQChvZzQUwDSgIrjoMPWcFNGu2pzSnQWWU7BB+DpX3jb7kHC/mLFj3M2Fxv7bCK51HWI6h3/+aZDnC9gbMWMgwWA==</X509Certificate>
							</ds:X509Data>
						</ds:KeyInfo>
					</md:KeyDescriptor>
					<md:KeyDescriptor use="encryption">
						<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
							<ds:X509Data>
								<X509Certificate>MIIFqTCCA5GgAwIBAgIJANnmNJJ15Nh+MA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTAeFw0xNzA4MjYwMDA4MThaFw0yNzA4MjQwMDA4MThaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPHgIgA/6mzofjwQjmFhY7lW8Hh1AG//efBtIRft3IlgqgQ8zmFDvBoo/kvWAUmYRDE/LQiPsjJuMF5gwRwN5wLOpnomfeyiurFOdSBT7lSLqvtZWP35H+FpuXaT/nJ2YupYNHABb6e0veXM3JN2KdoKsVts0RvNnfyi/aeKxnmgrnrRERR0yBdKIcsw2W4hGnB4Xp8vXG8ZNXzZZTVIMrYUAOCVjH+BviB4wqk63K6Nu4KnrVmCEAyw9xpIeHlMGmOnHdyoSUBlicbMJl90uxjjEzN5eAn6J3q+tzFeR/2c6BMJXVRZ2YDb/LWhKoaXK8kwzwyIQxUoXc7Soz4v+uWSNKh9oJSy757T0KlR+cu4z3o1tpjDv/QZc6xN9yJb7/Vg4shbVneHupa51K/HoRiXD/DEmA3daerEvcidj/Xrriui+J7sjXQ7mYu6/ISDrKSnX4R7nJ5FrQeiN/3NApVBGO1bqOi6dhv/GNQrAS5dmdCHjyL104kvyA/G7qdJ1iJVI1PlQEmU8kIpgxYyrMMZWhBfM1/+6PY8r57/NJm/G7u7eFKQQ1hk1x9e7uPfTjcdbCBwSPiPvy59cCkQ9P5NaOaYapmGoquyRnw3ZoqRDnC3PKttt47DzN5OK2mbLyaCppoubzYmZf+lG0nwddcd2sp0GdGHWLT0aiPaGtzzAgMBAAGjUDBOMB0GA1UdDgQWBBSjhCS8oXZKkctM4QyAzLyFSJuaLTAfBgNVHSMEGDAWgBSjhCS8oXZKkctM4QyAzLyFSJuaLTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQDjxydOEhvcpLM3Xoz28dlw4CsU9qev6Lokv5K4fj7qMFi6zkjSVrzQ8C0T2WfuU8eReTXhCwUbT+Vq2X5+S3zplmRhHmbKbclkj0C2LfQpqdqs6JGke9PsQOxkhzcIF4CDqMSrN6q60UeRPxQ8HM0tkh7EIXp83NINHOULDJgGl9yGGpiV00r0iPDh+y6rGEZMoKw1WOUghLkmMLemd8tELXDORgaofsjz14y3le7JiWkaKA6EbmJReSDrmjuqp0O2cs3bqUsHlLQ20VtrmPS1Lw6jABujC6NA0CxwwIY5MRRRnXjTrc31CRlBRhM9f9YpEeZuCy3k7UuK6zeP0cAY3Jtt78SMLxzemJu4RRNqFypTwue1uBlDC+zO6Cpjh+D54laptRfFIg/bZ91zR3KOESAsvEfVG9CShRxHocy6Q+6oy852Ry6T8blVP6/SOlvB9A++cMoO/idDQ4yGIKicM98zcenf72Hn3I1h5BiGNM8TBkZQ1OvZ/ItrtQvMAA0x4tbHI4YU0Z8SvKsDoxmCnnbynpL/7HCzPNd56hQq0EyHGtowZmqP9bZ7geyCnAHd449vL/drGSGyvElN6QsQChvZzQUwDSgIrjoMPWcFNGu2pzSnQWWU7BB+DpX3jb7kHC/mLFj3M2Fxv7bCK51HWI6h3/+aZDnC9gbMWMgwWA==</X509Certificate>
							</ds:X509Data>
						</ds:KeyInfo>
					</md:KeyDescriptor>
					<md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://example.com/auth/saml"
						index="0" isDefault="true" />
					<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/auth/logout"
						ResponseLocation="https://exa mple.com/auth/logout" />
					<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
					<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
					<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
					<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName</md:NameIDFormat>
					<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
						Location="https://example.com/auth/federation/sso" />
					<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/auth/federation/sso"
					/></md:IDPSSODescriptor>
				<md:AdditionalMetadataLocation namespace="urn:oasis:names:tc:SAML:2.0:metadata">https://exam ple.com/sp.xml</md:AdditionalMetadataLocation>
			</md:EntityDescriptor>`,
		},
		{
			Name: "Test 2",
			MetadataXML: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/sso">
			<IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
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
					<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc">
						<KeySize xmlns="http://www.w3.org/2001/04/xmlenc#">128</KeySize>
					</EncryptionMethod>
				</KeyDescriptor>
				<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://example.com/sso/ArtifactResolver/metaAlias/bns/idp"
					index="0" isDefault="1" />
				<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso/IDPSloRedirect/metaAlias/bns/idp"
					ResponseLocation="https://example.com/sso/IDPSloRedirect/metaAlias/bns/idp" />
				<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/sso/IDPSloPOST/metaAlias/bns/idp"
					ResponseLocation="https://example.com/sso/IDPSloPOST/metaAlias/bns/idp" />
				<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://example.com/sso/IDPSloSoap/metaAlias/bns/idp"
				/>
				<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso/IDPMniRedirect/metaAlias/bns/idp"
					ResponseLocation="https://example.com/sso/IDPMniRedirect/metaAlias/bns/idp" />
				<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/sso/IDPMniPOST/metaAlias/bns/idp"
					ResponseLocation="https://example.com/sso/IDPMniPOST/metaAlias/bns/idp" />
				<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://example.com/sso/IDPMniSoap/metaAlias/bns/idp"
				/>
				<NameIDFormat>
					urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
				</NameIDFormat>
				<NameIDFormat>
					urn:oasis:names:tc:SAML:2.0:nameid-format:transient
				</NameIDFormat>
				<NameIDFormat>
					urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
				</NameIDFormat>
				<NameIDFormat>
					urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
				</NameIDFormat>
				<NameIDFormat>
					urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName
				</NameIDFormat>
				<NameIDFormat>
					urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos
				</NameIDFormat>
				<NameIDFormat>
					urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName
				</NameIDFormat>
				<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso/SSORedirect/metaAlias/bns/idp"
				/>
				<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/sso/SSOPOST/metaAlias/bns/idp"
				/>
				<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://example.com/sso/SSOSoap/metaAlias/bns/idp"
				/>
				<NameIDMappingService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://example.com/sso/NIMSoap/metaAlias/bns/idp"
				/>
				<AssertionIDRequestService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://example.com/sso/AIDReqSoap/IDPRole/metaAlias/bns/idp"
				/>
				<AssertionIDRequestService Binding="urn:oasis:names:tc:SAML:2.0:bindings:URI" Location="https://example.com/sso/AIDReqUri/IDPRole/metaAlias/bns/idp"
				/>
			</IDPSSODescriptor>
		</EntityDescriptor>`,
		},
	}

	for _, tt := range tests {
		var metadata Metadata
		if err := xml.Unmarshal([]byte(tt.MetadataXML), &metadata); err != nil {
			t.Fatal(errors.Wrapf(err, "%v: failed to unmarshal metadata XML", tt.Name))
		}
	}
}
func TestDuration(t *testing.T) {
	tests := []struct {
		Name     string
		Value    string
		Valid    bool
		Duration string
	}{
		{
			Name:     `Valid duration`,
			Value:    `P10Y0M30DT0H0M0.000S`,
			Valid:    true,
			Duration: "88320h",
		},
		{
			Name:     `2 years, 6 months, 5 days, 12 hours, 35 minutes, 30 seconds`,
			Value:    `P2Y6M5DT12H35M30S`,
			Valid:    true,
			Duration: "22032h35m30s",
		},
		{
			Name:     `1 day, 2 hours`,
			Value:    `P1DT2H`,
			Valid:    true,
			Duration: "26h",
		},
		{
			Name:     `20 months (the number of months can be more than 12)`,
			Value:    `P20M`,
			Valid:    true,
			Duration: "14600h",
		},
		{
			Name:     `20 minutes`,
			Value:    `PT20M`,
			Valid:    true,
			Duration: "20m",
		},
		{
			Name:     `20 months (0 is permitted as a number, but is not required)`,
			Value:    `P0Y20M0D`,
			Valid:    true,
			Duration: "14600h",
		},
		{
			Name:     `0 years`,
			Value:    `P0Y`,
			Valid:    true,
			Duration: "0h",
		},
		{
			Name:     `minus 60 days`,
			Value:    `-P60D`,
			Valid:    true,
			Duration: "-1440h",
		},
		{
			Name:     `1 minute, 30.5 seconds`,
			Value:    `PT1M30.5S`,
			Valid:    true,
			Duration: "0h1m30.5s",
		},

		{
			Name:  `the minus sign must appear first`,
			Value: `P-20M`,
			Valid: false,
		},
		{
			Name:  `no time items are present, so "T" must not be present`,
			Value: `P20MT`,
			Valid: false,
		},
		{
			Name:  `no value is specified for months, so "M" must not be present`,
			Value: `P1YM5D`,
			Valid: false,
		},
		{
			Name:  `only the seconds can be expressed as a decimal`,
			Value: `P15.5Y`,
			Valid: false,
		},
		{
			Name:  `T" must be present to separate days and hours`,
			Value: `P1D2H`,
			Valid: false,
		},
		{
			Name:  `P" must always be present`,
			Value: `1Y2M`,
			Valid: false,
		},
		// TODO
		// {
		// 	Name:  `years must appear before months`,
		// 	Value: `P2M1Y`,
		// 	Valid: false,
		// },
		{
			Name:  `at least one number and designator are required`,
			Value: `P`,
			Valid: false,
		},
		{
			Name:  `at least one digit must follow the decimal point if it appears`,
			Value: `PT15.S`,
			Valid: false,
		},
		{
			Name:  "an empty value is not valid, unless xsi:nil is used",
			Value: ``,
			Valid: false,
		},
	}

	for _, tt := range tests {
		cacheDuration := &CacheDuration{}
		err := cacheDuration.UnmarshalXMLAttr(xml.Attr{Value: tt.Value})

		if tt.Valid && err != nil {
			t.Fatal(errors.Wrapf(err, "%v: failed to unmarshal duration (%v)", tt.Name, tt.Value))
		}

		if !tt.Valid && err == nil {
			t.Fatal(errors.Wrapf(err, "%v: expected duration unmarshalling to fail for (%v)", tt.Name, tt.Value))
		}

		if tt.Duration != "" {
			d, err := time.ParseDuration(tt.Duration)
			if err != nil {
				t.Fatal(errors.Wrapf(err, "%v: failed to parse duration (%v)", tt.Name, tt.Duration))
			}
			if cacheDuration.Duration() != d {
				t.Fatalf("%v: expected duration to be (%v) but got (%v)", tt.Name, d, cacheDuration.Duration())
			}
		}
	}
}
