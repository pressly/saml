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

// HTTPPostBinding is the official URN for the HTTP-POST binding (transport)
const HTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

// HTTPRedirectBinding is the official URN for the HTTP-Redirect binding (transport)
const HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

const ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"

const NameIDEntityFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

const NameIDEmailAddressFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

// AuthnRequest represents the SAML object of the same name, a request from a service provider
// to authenticate a user.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf sec 3.4.1 Element <AuthnRequest>
type AuthnRequest struct {
	// Since multiple namespaces can be used, don't hardcode in the element
	XMLName xml.Name
	// Spec lists that the xmlns also needs to be namespaced: https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
	// TODO: create custom marshaler
	XMLNamespace string `xml:"xmlns:samlp,attr,omitempty"`

	Signature *xmlsec.Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`

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

	// Optional attributes
	//

	// Identifies the entity that generated the request message
	// By default, the value of the <Issuer> element is a URI of no more than 1024 characters.
	// Changes from SAML version 1 to 2
	// An <Issuer> element can now be present on requests and responses (in addition to appearing on assertions).
	Issuer Issuer

	// A URI reference indicating the address to which this request has been sent. This is useful to prevent
	// malicious forwarding of requests to unintended recipients, a protection that is required by some
	// protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
	// location at which the message was received. If it does not, the request MUST be discarded. Some
	// protocol bindings may require the use of this attribute (see [SAMLBind]).
	Destination string `xml:",attr"`

	// Specifies by value the location to which the <Response> message MUST be returned to the
	// requester. The responder MUST ensure by some means that the value specified is in fact associated
	// with the requester. [SAMLMeta] provides one possible mechanism; signing the enclosing
	// <AuthnRequest> message is another. This attribute is mutually exclusive with the
	// AssertionConsumerServiceIndex attribute and is typically accompanied by the ProtocolBinding attribute.
	AssertionConsumerServiceURL string `xml:",attr"`

	// A URI reference that identifies a SAML protocol binding to be used when returning the <Response>
	// message. See [SAMLBind] for more information about protocol bindings and URI references defined
	// for them. This attribute is mutually exclusive with the AssertionConsumerServiceIndex attribute
	// and is typically accompanied by the AssertionConsumerServiceURL attribute.
	ProtocolBinding string `xml:",attr"`

	// Specifies constraints on the name identifier to be used to represent the requested subject.
	// If omitted, then any type of identifier supported by the identity provider for the requested
	// subject can be used, constrained by any relevant deployment-specific policies, with respect to privacy.
	NameIDPolicy NameIDPolicy
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
// Also refer to Azure docs for their IdP supported values: https://msdn.microsoft.com/en-us/library/azure/dn195589.aspx
type NameIDPolicy struct {
	XMLName xml.Name

	// Optional attributes
	//

	// A Boolean value used to indicate whether the identity provider is allowed, in the course of fulfilling the
	// request, to create a new identifier to represent the principal. Defaults to "false". When "false", the
	// requester constrains the identity provider to only issue an assertion to it if an acceptable identifier for
	// the principal has already been established. Note that this does not prevent the identity provider from
	// creating such identifiers outside the context of this specific request (for example, in advance for a
	// large number of principals)
	AllowCreate bool `xml:",attr"`

	// Specifies the URI reference corresponding to a name identifier format defined in this or another
	// specification (see Section 8.3 for examples). The additional value of
	// urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted is defined specifically for use
	// within this attribute to indicate a request that the resulting identifier be encrypted
	Format string `xml:",attr"`
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
	Status *Status

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
	Issuer *Issuer

	EncryptedAssertion *EncryptedAssertion

	Assertion *Assertion
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
	XMLName       xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
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
	Issuer             *Issuer
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
