package xmlsec

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptMarshalTemplate(t *testing.T) {
	emptyTemplate := NewEncryptedDataTemplate(
		"http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	)

	out, err := xml.MarshalIndent(emptyTemplate, "", "\t")
	assert.NoError(t, err)

	expectedOut := `<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
	<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>
	<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
		<EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">
			<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"></EncryptionMethod>
			<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
				<X509Data></X509Data>
			</KeyInfo>
			<CipherData xmlns="http://www.w3.org/2001/04/xmlenc#">
				<CipherValue></CipherValue>
			</CipherData>
		</EncryptedKey>
	</KeyInfo>
	<CipherData xmlns="http://www.w3.org/2001/04/xmlenc#">
		<CipherValue></CipherValue>
	</CipherData>
</EncryptedData>`

	assert.Equal(t, expectedOut, string(out))
}

func TestEncryptData(t *testing.T) {
	in := `<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/>
`

	tpl := NewEncryptedDataTemplate(
		"http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	)
	out, err := Encrypt(tpl, []byte(in), "_testdata/test.crt", "aes-128")
	assert.NoError(t, err)
	assert.NotEqual(t, string(in), string(out))

	out, err = Decrypt(out, "_testdata/test.key")
	if err != nil {
		if _, ok := err.(ErrSelfSignedCertificate); !ok {
			assert.NoError(t, err)
		}
	}
	assert.Equal(t, string(in), string(out))
}

func TestEncryptDataRSA(t *testing.T) {
	in := `<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/>
`
	tpl := NewEncryptedDataTemplate(
		"http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
		"http://www.w3.org/2001/04/xmlenc#rsa-1_5",
	)
	out, err := Encrypt(tpl, []byte(in), "_testdata/test.crt", "des-192")
	assert.NoError(t, err)
	assert.NotEqual(t, string(in), string(out))

	out, err = Decrypt(out, "_testdata/test.key")
	if err != nil {
		if _, ok := err.(ErrSelfSignedCertificate); !ok {
			assert.NoError(t, err)
		}
	}
	assert.Equal(t, string(in), string(out))
}

func TestEncryptDataRSA2(t *testing.T) {
	in := `<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/>
`
	tpl := NewEncryptedDataTemplate(
		"http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
		"http://www.w3.org/2001/04/xmlenc#rsa-1_5",
	)
	out, err := Encrypt(tpl, []byte(in), "_testdata/test.crt", "des-192")
	assert.NoError(t, err)
	assert.NotEqual(t, string(in), string(out))

	out, err = Decrypt(out, "_testdata/test.key")
	if err != nil {
		if _, ok := err.(ErrSelfSignedCertificate); !ok {
			assert.NoError(t, err)
		}
	}
	assert.Equal(t, string(in), string(out))
}
