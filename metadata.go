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

package saml

import (
	"encoding/xml"
	"time"
)

// HTTPPostBinding is the official URN for the HTTP-POST binding (transport)
const HTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

// HTTPRedirectBinding is the official URN for the HTTP-Redirect binding (transport)
const HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

// EntitiesDescriptor represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.3.1
type EntitiesDescriptor struct {
	XMLName          xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	EntityDescriptor []*Metadata `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
}

// Metadata represents the SAML EntityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.3.2
type Metadata struct {
	XMLName          xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	ValidUntil       time.Time         `xml:"validUntil,attr"`
	CacheDuration    time.Duration     `xml:"cacheDuration,attr,omitempty"`
	EntityID         string            `xml:"entityID,attr"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor"`
}

// KeyDescriptor represents the XMLSEC object of the same name
type KeyDescriptor struct {
	Use               string             `xml:"use,attr"`
	KeyInfo           KeyInfo            `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

// EncryptionMethod represents the XMLSEC object of the same name
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo represents the XMLSEC object of the same name
type KeyInfo struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	Certificate string   `xml:"X509Data>X509Certificate"`
}

// Endpoint represents the SAML EndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.2.2
type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

// IndexedEndpoint represents the SAML IndexedEndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.2.3
type IndexedEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}

// SPSSODescriptor represents the SAML SPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.4.2
type SPSSODescriptor struct {
	XMLName                    xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	AuthnRequestsSigned        bool              `xml:",attr"`
	WantAssertionsSigned       bool              `xml:",attr"`
	ProtocolSupportEnumeration string            `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              []KeyDescriptor   `xml:"KeyDescriptor"`
	ArtifactResolutionService  []IndexedEndpoint `xml:"ArtifactResolutionService"`
	SingleLogoutService        []Endpoint        `xml:"SingleLogoutService"`
	ManageNameIDService        []Endpoint
	NameIDFormat               []string          `xml:"NameIDFormat"`
	AssertionConsumerService   []IndexedEndpoint `xml:"AssertionConsumerService"`
	AttributeConsumingService  []interface{}
}

// IDPSSODescriptor represents the SAML IDPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.4.3
type IDPSSODescriptor struct {
	XMLName                    xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	ProtocolSupportEnumeration string          `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              []KeyDescriptor `xml:"KeyDescriptor"`
	NameIDFormat               []string        `xml:"NameIDFormat"`
	SingleSignOnService        []Endpoint      `xml:"SingleSignOnService"`
}

// EmptyMetadata is an empty metadata value.
var EmptyMetadata = Metadata{}
