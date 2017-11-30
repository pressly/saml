package xmlsec

import (
	"encoding/xml"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const signatureTemplate = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <Reference>
      <Transforms>
        <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </Transforms>
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue />
    </Reference>
    </SignedInfo>
  <SignatureValue />
  <KeyInfo>
    <X509Data />
  </KeyInfo>
</Signature>`

func TestVerifyFail(t *testing.T) {
	badDocument := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<document>
  <firstelement attr1="attr1">
    Content of first element.
    <secondelement attr2="attr2">
      Content of the second element.
      <thirdelement attr3="attr3">
        And the content of the third element.
      </thirdelement>
    </secondelement>
  </firstelement>
	<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <Reference>
      <Transforms>
        <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </Transforms>
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue>dZrvFdaRZNqvOMBoHACmIE5X13g=</DigestValue>
    </Reference>
    </SignedInfo>
  <SignatureValue>uc5UxTqMslYA9yEwh3nSqhWA8KNDfjmf+VcCjUJebeVEx+lbaGpmlm9GJeT9SO2w
M1cZxGVbg6f53aHRqYM4rvH9lQhlkJIHW8Onj9qBZFF54ZFBXAP2HsPFAtavSv+v
1fKsyyNTPDRJuLZQFN54okfq7NZZgiPRlHLTA0I8AXc/yuiqwAwoiJkjN6lymVvt
yuZkY+yqxxxhnjPCOvT7dHDDgNDDxpMB++/i+t5tWg4LmtcKWRRWnOVAH88cpd4y
auCn/mR9IhcxbXZBGurhMxAePbxLF7MlP6a6hUy7hVT1EXD7dkvbyJ+wSn5ZZOZf
82R8JsTqp0OOy86D3XcWwX==</SignatureValue>
  <KeyInfo>
    <X509Data/>
  </KeyInfo>
</Signature>
</document>
`)

	err := Verify(badDocument, "_testdata/test.crt", &ValidationOptions{
		IDAttrs:          []string{"document"},
		EnableIDAttrHack: true,
	})
	assert.Error(t, err)
}

func TestSignAndVerify(t *testing.T) {
	testIn := `<?xml version="1.0" encoding="UTF-8"?>
<document>
  <firstelement attr1="attr1">
    Content of first element.
    <secondelement attr2="attr2">
      Content of the second element.
      <thirdelement attr3="attr3">
        And the content of the third element.
      </thirdelement>
    </secondelement>
  </firstelement>
	` + signatureTemplate + `
</document>`

	out, err := Sign([]byte(testIn), "_testdata/test.key", &ValidationOptions{
		EnableIDAttrHack: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedOut := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<document>
  <firstelement attr1="attr1">
    Content of first element.
    <secondelement attr2="attr2">
      Content of the second element.
      <thirdelement attr3="attr3">
        And the content of the third element.
      </thirdelement>
    </secondelement>
  </firstelement>
	<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <Reference>
      <Transforms>
        <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </Transforms>
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue>dZrvFdaRZNqvOMBoHACmIE5X13g=</DigestValue>
    </Reference>
    </SignedInfo>
  <SignatureValue>yiaFcqnjLRe4SFQXAGULtcYy7QPQy8DyX+t1Z4tfVitakOCRu0Yn52nKc+JQCX28
ziTB5dGVze4wn4xuNcBYQ2cQ0v5oUNaqqjtR6AW+AvCc5x8NDa1LlRv3F4Mcx7E1
UOtapGkSaG8y8vXX9QYOBNspAGHjqkgiyin2UVmRGn1dcZ3xxlqWVTbdwOcyTL20
RnLe62TzsDCkxdqaDh0OfZyVBakrU3wlSkk81Be8LnTrY+F7cL/JGU6r8qCkvdFi
FY7bQrOPS73L5HPtsAsmInM8SgP+3deBDoqMUVf+pbJ7SDtrjs9ZQy2JkeAF6/C3
ohv8eaTdiOUc7qf1L7oIV/oFgaidMj+j+SIQvkDFcrhip45TS2eL1w/NOBVdCB7U
gXKQBmQqV0Y4YJLXMMWx9RHjj8UMXEDEeY8EHyLMSGxaYu+qJyykbtMWmQAGhYcX
MojSiiJJtWNAm/ijORoYfdaZrXBfGbJuOzfFYQiieYyS4wreiAwetG2sYmD35t6I
f2rLW19XQc67dmFb0QgmfaRVNnMeeYo6AhNRzZyM1ItVDYzao6HDAf8plk+kYZpL
4QjjSejy7I+8Jqeg7lDRO2pcAskHX3Kuy4dkT7FKh5kCeAAyrkdrMpgLtJ+ihuj9
3LHLkkivMUKF/+g97npEjs4rgO5hcGztac9EHCdj6Cs=</SignatureValue>
  <KeyInfo>
    <X509Data/>
  </KeyInfo>
</Signature>
</document>
`)

	assert.Equal(t, string(expectedOut), string(out))

	err = Verify(out, "_testdata/test.crt", &ValidationOptions{
		EnableIDAttrHack: true,
	})
	assert.NoError(t, err)
}

func TestSignAndVerifyNode(t *testing.T) {
	fp, err := os.Open("_testdata/test.crt")
	assert.NoError(t, err)
	defer fp.Close()

	crt, err := ioutil.ReadAll(fp)
	assert.NoError(t, err)

	type Address struct {
		City, State string
	}
	type Person struct {
		XMLName   xml.Name `xml:"person"`
		ID        int      `xml:"id,attr"`
		FirstName string   `xml:"name>first"`
		LastName  string   `xml:"name>last"`
		Age       int      `xml:"age"`
		Height    float32  `xml:"height,omitempty"`
		Married   bool
		Address
		Comment string `xml:",comment"`
	}

	person := &Person{ID: 13, FirstName: "John", LastName: "Doe", Age: 42}
	person.Comment = " Need more details. "
	person.Address = Address{"Hanga Roa", "Easter Island"}

	type Envelope struct {
		XMLName   xml.Name `xml:"envelope"`
		Person    Person
		Signature Signature
	}

	e := Envelope{Person: *person, Signature: DefaultSignature(crt)}

	xmlDoc, err := xml.Marshal(e)

	out, err := Sign([]byte(xmlDoc), "_testdata/test.key", &ValidationOptions{
		EnableIDAttrHack: true,
	})
	if err != nil {
		if _, ok := err.(ErrSelfSignedCertificate); !ok {
			assert.NoError(t, err)
		}
	}

	expectedOut := []byte(`<?xml version="1.0"?>
<envelope><person id="13"><name><first>John</first><last>Doe</last></name><age>42</age><Married>false</Married><City>Hanga Roa</City><State>Easter Island</State><!-- Need more details. --></person><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>yFthc0ToZkk8FvNs1pIb9NYcIg8=</DigestValue></Reference></SignedInfo><SignatureValue>Z7E3BmVKKeLmloleTN0DboGbYjVluvv/FvjMKkc29xDEPyAyF5HpHyk3hHXJ1hHm
ZB9SYRKoVY/UJ7+W6S/koa6n5GKAWIDVjlHBityzQW8GQrDiDgxrt9Pt+fBc3RKH
dHYUVVM5+wGRQRonfaxtIrCLiDe0Uaz8eBwtvBchlJ7zssBszp+7QrP4D9yH++sY
n1qRQ3sW1ZD2YanpyZyWwI7huoHuldYOimf7bIX/uCVcTMWIbx0kU7jXJZj3OCAz
vpY5WbLlQSg6pcdYcAvDIgqV+p7/iuOpguagKktW6EnJgE7AYuaJWHeNKzc31vZY
MDzSHfPhFDR9+Ag+QM7wz6kTS916DM3Ic6CTGki0fFza+PoErmuMqsm8xxyFUGGV
/GYbIOA6CKXOHw0L/LFYVVeR7n7p1R1E+tfv+1cFKqlod5Xz+88sMzxbLLzNSwGl
oJqoWUgvXLEHpMNNEJ9YCiYz3sDObUrlsDlu2z8NBM+k17EJXl9EOo8381rC5wCr
TMrz2omwet+yk4DwbQW3I5a73eh4jMbYQl1zhT5yrBBSypcHSikv1fZmF146ueja
LwHiqTZeqrecl6edzjte9c/vMcvaKUVnZQWmsSkjgwQI/8kaYuw0Hiv/RKJighWV
h5BC02ePIIwd58lPjdsQUrgetVnDh3DyuKtMqufVmNw=</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIFqTCCA5GgAwIBAgIJANnmNJJ15Nh+MA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTAeFw0xNzA4MjYwMDA4MThaFw0yNzA4MjQwMDA4MThaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRAwDgYDVQQKDAdQcmVzc2x5MQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5wcmVzc2x5LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPHgIgA/6mzofjwQjmFhY7lW8Hh1AG//efBtIRft3IlgqgQ8zmFDvBoo/kvWAUmYRDE/LQiPsjJuMF5gwRwN5wLOpnomfeyiurFOdSBT7lSLqvtZWP35H+FpuXaT/nJ2YupYNHABb6e0veXM3JN2KdoKsVts0RvNnfyi/aeKxnmgrnrRERR0yBdKIcsw2W4hGnB4Xp8vXG8ZNXzZZTVIMrYUAOCVjH+BviB4wqk63K6Nu4KnrVmCEAyw9xpIeHlMGmOnHdyoSUBlicbMJl90uxjjEzN5eAn6J3q+tzFeR/2c6BMJXVRZ2YDb/LWhKoaXK8kwzwyIQxUoXc7Soz4v+uWSNKh9oJSy757T0KlR+cu4z3o1tpjDv/QZc6xN9yJb7/Vg4shbVneHupa51K/HoRiXD/DEmA3daerEvcidj/Xrriui+J7sjXQ7mYu6/ISDrKSnX4R7nJ5FrQeiN/3NApVBGO1bqOi6dhv/GNQrAS5dmdCHjyL104kvyA/G7qdJ1iJVI1PlQEmU8kIpgxYyrMMZWhBfM1/+6PY8r57/NJm/G7u7eFKQQ1hk1x9e7uPfTjcdbCBwSPiPvy59cCkQ9P5NaOaYapmGoquyRnw3ZoqRDnC3PKttt47DzN5OK2mbLyaCppoubzYmZf+lG0nwddcd2sp0GdGHWLT0aiPaGtzzAgMBAAGjUDBOMB0GA1UdDgQWBBSjhCS8oXZKkctM4QyAzLyFSJuaLTAfBgNVHSMEGDAWgBSjhCS8oXZKkctM4QyAzLyFSJuaLTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQDjxydOEhvcpLM3Xoz28dlw4CsU9qev6Lokv5K4fj7qMFi6zkjSVrzQ8C0T2WfuU8eReTXhCwUbT+Vq2X5+S3zplmRhHmbKbclkj0C2LfQpqdqs6JGke9PsQOxkhzcIF4CDqMSrN6q60UeRPxQ8HM0tkh7EIXp83NINHOULDJgGl9yGGpiV00r0iPDh+y6rGEZMoKw1WOUghLkmMLemd8tELXDORgaofsjz14y3le7JiWkaKA6EbmJReSDrmjuqp0O2cs3bqUsHlLQ20VtrmPS1Lw6jABujC6NA0CxwwIY5MRRRnXjTrc31CRlBRhM9f9YpEeZuCy3k7UuK6zeP0cAY3Jtt78SMLxzemJu4RRNqFypTwue1uBlDC+zO6Cpjh+D54laptRfFIg/bZ91zR3KOESAsvEfVG9CShRxHocy6Q+6oy852Ry6T8blVP6/SOlvB9A++cMoO/idDQ4yGIKicM98zcenf72Hn3I1h5BiGNM8TBkZQ1OvZ/ItrtQvMAA0x4tbHI4YU0Z8SvKsDoxmCnnbynpL/7HCzPNd56hQq0EyHGtowZmqP9bZ7geyCnAHd449vL/drGSGyvElN6QsQChvZzQUwDSgIrjoMPWcFNGu2pzSnQWWU7BB+DpX3jb7kHC/mLFj3M2Fxv7bCK51HWI6h3/+aZDnC9gbMWMgwWA==</X509Certificate></X509Data></KeyInfo></Signature></envelope>
`)

	assert.Equal(t, string(expectedOut), string(out))
}
