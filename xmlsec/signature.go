// Copyright (c) 2015, Ross Kinder
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package xmlsec

import (
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
)

// Method is part of Signature.
type Method struct {
	Algorithm string `xml:",attr"`
}

// Signature is a model for the Signature object specified by XMLDSIG. This is
// convenience object when constructing XML that you'd like to sign. For example:
//
//    type Foo struct {
//       Stuff string
//       Signature Signature
//    }
//
//    f := Foo{Suff: "hello"}
//    f.Signature = DefaultSignature()
//    buf, _ := xml.Marshal(f)
//    buf, _ = Sign(key, buf)
//
type Signature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`

	CanonicalizationMethod Method             `xml:"SignedInfo>CanonicalizationMethod"`
	SignatureMethod        Method             `xml:"SignedInfo>SignatureMethod"`
	ReferenceTransforms    []Method           `xml:"SignedInfo>Reference>Transforms>Transform"`
	DigestMethod           Method             `xml:"SignedInfo>Reference>DigestMethod"`
	DigestValue            string             `xml:"SignedInfo>Reference>DigestValue"`
	SignatureValue         string             `xml:"SignatureValue"`
	KeyName                string             `xml:"KeyInfo>KeyName,omitempty"`
	X509Certificate        *SignatureX509Data `xml:"KeyInfo>X509Data,omitempty"`
}

// SignatureX509Data represents the <X509Data> element of <Signature>
type SignatureX509Data struct {
	X509Certificate string `xml:"X509Certificate,omitempty"`
}

// DefaultSignature returns a Signature struct that uses the default c14n and SHA1 settings.
func DefaultSignature(pemEncodedPublicKey []byte) Signature {
	// xmlsec wants the key to be base64-encoded but *not* wrapped with the
	// PEM flags
	pemBlock, _ := pem.Decode(pemEncodedPublicKey)
	certStr := base64.StdEncoding.EncodeToString(pemBlock.Bytes)

	return Signature{
		CanonicalizationMethod: Method{
			Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
		},
		SignatureMethod: Method{
			Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		},
		ReferenceTransforms: []Method{
			Method{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
		},
		DigestMethod: Method{
			Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
		},
		X509Certificate: &SignatureX509Data{
			X509Certificate: certStr,
		},
	}
}
