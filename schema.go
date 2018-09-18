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

	"github.com/goware/saml/xmlsec"
)

// AuthnRequest represents the SAML object of the same name, a request from a service provider
// to authenticate a user.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnRequest struct {
	XMLName                     xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	AssertionConsumerServiceURL string            `xml:",attr"`
	Destination                 string            `xml:",attr"`
	ID                          string            `xml:",attr"`
	IssueInstant                time.Time         `xml:",attr"`
	ProtocolBinding             string            `xml:",attr"`
	Version                     string            `xml:",attr"`
	Issuer                      Issuer            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature                   *xmlsec.Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	NameIDPolicy                NameIDPolicy      `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

// Issuer represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}

// NameIDPolicy represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	AllowCreate bool     `xml:",attr"`
	Format      string   `xml:",chardata"`
}

// Response represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 3.2
type Response struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`

	// Required attributes
	//

	// An identifier for the request.
	// The values of the ID attribute in a request and the InResponseTo
	// attribute in the corresponding response MUST match.
	ID string `xml:",attr"`

	// The version of this request.
	// Only version 2.0 is supported by goware/saml
	Version string `xml:",attr"`

	// The time instant of issue of the request. The time value is encoded in UTC
	IssueInstant time.Time `xml:",attr"`

	// A code representing the status of the corresponding reques
	Status *Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	// Optional attributes
	//

	// A URI reference indicating the address to which this request has been sent. This is useful to prevent
	// malicious forwarding of requests to unintended recipients, a protection that is required by some
	// protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
	// location at which the message was received. If it does not, the request MUST be discarded. Some
	// protocol bindings may require the use of this attribute
	Destination string `xml:",attr"`

	// An XML Signature that authenticates the requester and provides message integrity
	Signature *xmlsec.Signature

	// A reference to the identifier of the request to which the response corresponds, if any. If the response
	// is not generated in response to a request, or if the ID attribute value of a request cannot be
	// determined (for example, the request is malformed), then this attribute MUST NOT be present.
	// Otherwise, it MUST be present and its value MUST match the value of the corresponding request's
	// ID attribute.
	InResponseTo string `xml:",attr"`

	// Identifies the entity that generated the request message
	// By default, the value of the <Issuer> element is a URI of no more than 1024 characters.
	// Changes from SAML version 1 to 2
	// An <Issuer> element can now be present on requests and responses (in addition to appearing on assertions).
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`

	EncryptedAssertion *EncryptedAssertion

	Assertion *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	XMLText []byte `xml:"-"`
}

// Status represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Status struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode StatusCode
}

// StatusCode represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:",attr"`
}

// StatusSuccess is the value of a StatusCode element when the authentication succeeds.
// (nominally a constant, except for testing)
var StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// EncryptedAssertion represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type EncryptedAssertion struct {
	Assertion     *Assertion
	EncryptedData []byte `xml:",innerxml"`
}

// Assertion represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Assertion struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string    `xml:",attr"`
	IssueInstant       time.Time `xml:",attr"`
	Version            string    `xml:",attr"`
	Issuer             *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature          *xmlsec.Signature
	Subject            *Subject
	Conditions         *Conditions
	AuthnStatement     *AuthnStatement
	AttributeStatement *AttributeStatement
}

// Subject represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Subject struct {
	XMLName             xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              *NameID
	SubjectConfirmation *SubjectConfirmation
}

// NameID represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameID struct {
	Format          string `xml:",attr"`
	NameQualifier   string `xml:",attr"`
	SPNameQualifier string `xml:",attr"`
	Value           string `xml:",chardata"`
}

// SubjectConfirmation represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmation struct {
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

// SubjectConfirmationData represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmationData struct {
	Address      string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	NotOnOrAfter time.Time `xml:",attr"`
	Recipient    string    `xml:",attr"`
}

// Conditions represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Conditions struct {
	NotBefore           time.Time `xml:",attr"`
	NotOnOrAfter        time.Time `xml:",attr"`
	AudienceRestriction *AudienceRestriction
}

// AudienceRestriction represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AudienceRestriction struct {
	Audience *Audience
}

// Audience represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Audience struct {
	Value string `xml:",chardata"`
}

// AuthnStatement represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnStatement struct {
	AuthnInstant    time.Time `xml:",attr"`
	SessionIndex    string    `xml:",attr"`
	SubjectLocality SubjectLocality
	AuthnContext    AuthnContext
}

// SubjectLocality represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectLocality struct {
	Address string `xml:",attr"`
}

// AuthnContext represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnContext struct {
	AuthnContextClassRef *AuthnContextClassRef
}

// AuthnContextClassRef represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnContextClassRef struct {
	Value string `xml:",chardata"`
}

// AttributeStatement represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

// Attribute represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Attribute struct {
	FriendlyName string           `xml:",attr"`
	Name         string           `xml:",attr"`
	NameFormat   string           `xml:",attr"`
	Values       []AttributeValue `xml:"AttributeValue"`
}

// AttributeValue represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeValue struct {
	Type   string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value  string `xml:",chardata"`
	NameID *NameID
}
