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
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
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
	CacheDuration    *CacheDuration    `xml:"cacheDuration,attr,omitempty"`
	EntityID         string            `xml:"entityID,attr"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor"`
}

func (metadata *Metadata) Cert() string {
	// TODO: review logic for getting cert from metadata
	for _, keyDescriptor := range metadata.IDPSSODescriptor.KeyDescriptor {
		if keyDescriptor.Use == "encryption" {
			return keyDescriptor.KeyInfo.Certificate
		}
	}
	for _, keyDescriptor := range metadata.IDPSSODescriptor.KeyDescriptor {
		if keyDescriptor.KeyInfo.Certificate != "" {
			return keyDescriptor.KeyInfo.Certificate
		}
	}
	return ""
}

func (metadata *Metadata) SSOService(binding string) *Endpoint {
	log.Printf("Metadata.SSOService - binding: %v", binding)
	log.Printf("IDPSSODescriptor: %+v", metadata.IDPSSODescriptor)
	if metadata.IDPSSODescriptor == nil {
		return nil
	}

	for _, endpoint := range metadata.IDPSSODescriptor.SingleSignOnService {
		if binding == endpoint.Binding {
			return &endpoint
		}
	}
	return nil
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

type CacheDuration struct {
	raw    string
	attr   xml.Attr
	parsed time.Duration
}

func (duration *CacheDuration) Duration() time.Duration {
	return duration.parsed
}

func (duration *CacheDuration) MarshalAttr(name xml.Name) (xml.Attr, error) {
	// TODO: build cacheDuration from time.Duration
	return duration.attr, nil
}

func (duration *CacheDuration) UnmarshalXMLAttr(attr xml.Attr) error {
	duration.attr = attr
	duration.raw = attr.Value

	var err error
	if duration.parsed, err = ParseCacheDuration(attr.Value); err != nil {
		return errors.Wrapf(err, "invalid duration (%v)", attr.Value)
	}

	return nil
}

// ParseCacheDuration reads a xsd:duration from the metadata payload and converts into a time.Duration
//
// See http://www.datypic.com/sc/xsd/t-xsd_duration.html
func ParseCacheDuration(value string) (time.Duration, error) {
	var year, month, day, hour, minute, second string

	// "P" must always be present
	// "P" can only be followed by the minus sign
	if !strings.HasPrefix(value, "P") && !strings.HasPrefix(value, "-") {
		return time.Duration(0), errors.Errorf("missing P")
	}

	// at least one number and designator are required
	if len(value) < 3 {
		return time.Duration(0), errors.Errorf("missing designator")
	}

	// "T" must be present to separate days and hours
	// TODO: valid minutes
	if strings.ContainsAny(value, "HS") && !strings.ContainsAny(value, "T") {
		return time.Duration(0), errors.Errorf("T not present")
	}

	// no time items are present, so "T" must not be present
	// TODO: valid minutes
	if strings.ContainsAny(value, "T") && !strings.ContainsAny(value, "HMS") {
		return time.Duration(0), errors.Errorf("T should not be present")
	}
	if strings.ContainsAny(value, "T") && (strings.LastIndex(value, "T") == len(value)-1) {
		return time.Duration(0), errors.Errorf("T should not be present")
	}

	// the minus sign must appear first
	minusIndex := strings.IndexAny(value, "-")
	if minusIndex != -1 && minusIndex != 0 {
		return time.Duration(0), errors.Errorf("minus sign in wrong position")
	}

	// an empty value is not valid, unless xsi:nil is used
	if value == "" {
		return time.Duration(0), errors.Errorf("empty value")
	}

	var re *regexp.Regexp
	var parts []string

	// Parse year
	re = regexp.MustCompile(`\d+Y|\d*\.\d*Y`)
	parts = re.FindAllString(value, -1)
	if len(parts) > 1 {
		return time.Duration(0), errors.Errorf("found %d Y occurances", len(parts))
	}
	if len(parts) > 0 {
		parts = strings.Split(parts[0], "Y")
		if len(parts) != 2 {
			return time.Duration(0), errors.Errorf("failed to parse Y")
		}
		year = parts[0]
	}

	re = regexp.MustCompile(`\d+M|\d*\.\d*M`)
	parts = re.FindAllString(value, -1)
	if len(parts) == 0 && strings.ContainsAny(value, "M") {
		return time.Duration(0), errors.Errorf("found M without value")
	}

	if len(parts) == 2 {
		// Parse month
		monthParts := strings.Split(parts[0], "M")
		if len(monthParts) != 2 {
			return time.Duration(0), errors.Errorf("failed to parse M(month)")
		}
		month = monthParts[0]

		// Parse minute
		minParts := strings.Split(parts[1], "M")
		if len(minParts) != 2 {
			return time.Duration(0), errors.Errorf("failed to parse M(minute)")
		}
		minute = minParts[0]
	} else if len(parts) == 1 {
		if !strings.ContainsAny(value, "T") {
			// Parse month
			parts = strings.Split(parts[0], "M")
			if len(parts) != 2 {
				return time.Duration(0), errors.Errorf("failed to parse M(month)")
			}
			month = parts[0]
		} else {
			tPos := strings.IndexAny(value, "T")
			mPos := strings.IndexAny(value, "M")

			if tPos > mPos {
				// Parse month
				parts = strings.Split(parts[0], "M")
				if len(parts) != 2 {
					return time.Duration(0), errors.Errorf("failed to parse M(month)")
				}
				month = parts[0]
			} else {
				// Parse minute
				parts = strings.Split(parts[0], "M")
				if len(parts) != 2 {
					return time.Duration(0), errors.Errorf("failed to parse M(minute)")
				}
				minute = parts[0]
			}
		}
	} else if len(parts) > 2 {
		return time.Duration(0), errors.Errorf("found %d M occurances", len(parts))
	}

	// Parse day
	re = regexp.MustCompile(`\d+D|\d*\.\d*D`)
	parts = re.FindAllString(value, -1)
	if len(parts) == 0 && strings.ContainsAny(value, "D") {
		return time.Duration(0), errors.Errorf("found empty D")
	}
	if len(parts) > 1 {
		return time.Duration(0), errors.Errorf("found %d D occurances", len(parts))
	}
	if len(parts) > 0 {
		parts = strings.Split(parts[0], "D")
		if len(parts) != 2 {
			return time.Duration(0), errors.Errorf("failed to parse D")
		}
		day = parts[0]
	}

	// Parse hour
	re = regexp.MustCompile(`\d+H|\d*\.\d*H`)
	parts = re.FindAllString(value, -1)
	if len(parts) == 0 && strings.ContainsAny(value, "H") {
		return time.Duration(0), errors.Errorf("found empty H")
	}
	if len(parts) > 1 {
		return time.Duration(0), errors.Errorf("found %d H occurances", len(parts))
	}
	if len(parts) > 0 {
		parts = strings.Split(parts[0], "H")
		if len(parts) != 2 {
			return time.Duration(0), errors.Errorf("failed to parse H")
		}
		hour = parts[0]
	}

	// Parse second
	re = regexp.MustCompile(`\d+S|\d*\.\d*S`)
	parts = re.FindAllString(value, -1)
	if len(parts) == 0 && strings.ContainsAny(value, "S") {
		return time.Duration(0), errors.Errorf("found empty S")
	}
	if len(parts) > 1 {
		return time.Duration(0), errors.Errorf("found %d S occurances", len(parts))
	}
	if len(parts) > 0 {
		parts = strings.Split(parts[0], "S")
		if len(parts) != 2 {
			return time.Duration(0), errors.Errorf("failed to parse S")
		}
		second = parts[0]
	}

	// Validate input
	re = regexp.MustCompile(`[^\d]`)
	if re.MatchString(year) {
		return time.Duration(0), errors.Errorf("found invalid char for Y")
	}
	if re.MatchString(month) {
		return time.Duration(0), errors.Errorf("found invalid char for M(month)")
	}
	if re.MatchString(day) {
		return time.Duration(0), errors.Errorf("found invalid char for D")
	}
	if re.MatchString(hour) {
		return time.Duration(0), errors.Errorf("found invalid char for H")
	}
	if re.MatchString(minute) {
		return time.Duration(0), errors.Errorf("found invalid char for M(minute)")
	}

	secDotIndex := strings.LastIndex(second, ".")
	if secDotIndex != -1 && secDotIndex == len(second)-1 {
		return time.Duration(0), errors.Errorf("found S with invalid decimal number")
	}

	// Sum the total hours of the year,months and days defined in the cachedDuration value
	var dHour, dMinute int64
	var dSecond float64
	var i int64
	var err error
	if year != "" {
		if i, err = strconv.ParseInt(year, 10, 64); err != nil {
			return time.Duration(0), errors.Wrapf(err, "failed to parse year %v", year)
		}
		dHour += i * 8760 // number of hours in a year
	}

	if month != "" {
		if i, err = strconv.ParseInt(month, 10, 64); err != nil {
			return time.Duration(0), errors.Wrapf(err, "failed to parse month %v", month)
		}
		dHour += i * 730 // number of hours in a month
	}

	if day != "" {
		if i, err = strconv.ParseInt(day, 10, 64); err != nil {
			return time.Duration(0), errors.Wrapf(err, "failed to parse day %v", day)
		}
		dHour += i * 24 // number of hours in a day
	}

	if hour != "" {
		if i, err = strconv.ParseInt(hour, 10, 64); err != nil {
			return time.Duration(0), errors.Wrapf(err, "failed to parse hour %v", hour)
		}
		dHour += i
	}

	if minute != "" {
		if i, err = strconv.ParseInt(minute, 10, 64); err != nil {
			return time.Duration(0), errors.Wrapf(err, "failed to parse minute %v", minute)
		}
		dMinute = i
	}

	if second != "" {
		var f float64
		if f, err = strconv.ParseFloat(second, 64); err != nil {
			return time.Duration(0), errors.Wrapf(err, "failed to parse second %v", second)
		}
		dSecond = f
	}

	durString := fmt.Sprintf("%vh%vm%vs", dHour, dMinute, dSecond)
	// Mark duration as negative
	if strings.ContainsAny(value, "-") {
		durString = fmt.Sprintf("-%v", durString)
	}
	d, err := time.ParseDuration(durString)
	if err != nil {
		return time.Duration(0), errors.Wrapf(err, "failed to parse duration %v", durString)
	}
	return d, nil
}
