package xmlsec

// EncryptedData represents the <EncryptedData> XML tag. See
// https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Usage
type EncryptedData struct {
	XMLName          string     `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedData"`
	Type             string     `xml:",attr"`
	EncryptionMethod Method     `xml:"EncryptionMethod"`
	KeyInfo          KeyInfo    `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	CipherData       CipherData `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
}

// CipherData represents the <CipherData> tag.
type CipherData struct {
	CipherValue string `xml"CipherValue"`
}

// KeyInfo represents the <KeyInfo> tag.
type KeyInfo struct {
	EncryptedKey EncryptedKey `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
}

// EncryptedKey represents the <EncryptedKey> XML element. See
// https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-EncryptedKey
type EncryptedKey struct {
	EncryptionMethod Method `xml:"EncryptionMethod"`
	KeyInfo          struct {
		X509Data string
	} `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	CipherData CipherData `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
}

const (
	defaultDataEncryptionMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	defaultKeyEncryptionMethodAlgorithm  = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
)

// NewEncryptedDataTemplate returns an EncryptedData object that uses the given
// data and key encryption algorithms.
func NewEncryptedDataTemplate(dataEncryptionMethodAlgorithm string, keyEncryptionMethodAlgorithm string) *EncryptedData {
	return &EncryptedData{
		Type: "http://www.w3.org/2001/04/xmlenc#Element",
		EncryptionMethod: Method{
			Algorithm: dataEncryptionMethodAlgorithm,
		},
		KeyInfo: KeyInfo{
			EncryptedKey: EncryptedKey{
				EncryptionMethod: Method{
					Algorithm: keyEncryptionMethodAlgorithm,
				},
			},
		},
	}
}
