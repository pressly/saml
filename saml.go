// MIT License
//
// Copyright (c) 2017 Pressly Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package saml provides a Single Sign On (SSO) implementation using SAML.
package saml

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/pressly/saml/xmlsec"
	"github.com/satori/go.uuid"
)

const defaultValidDuration = time.Hour * 24 * 2

// MaxIssueDelay is the maximum timeframe where an assertion can be considered
// valid.
const MaxIssueDelay = time.Second * 90

// Now is a function that returns the current time. This vale can be
// overwritten during tests.
var Now = time.Now

// NewID is a function that returns a unique identifier. This value can be
// overwritten during tests.
var NewID = func() string {
	return fmt.Sprintf("id-%x", uuid.NewV4())
}

// GetMetadata takes the URL of a metadata.xml file, downloads and parses it.
// Returns a *Metadata value.
func GetMetadata(metadataURL string) (*Metadata, error) {
	res, err := http.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var metadata Metadata
	err = xml.Unmarshal(buf, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

// Logf prints log messages to stdout.
func Logf(format string, v ...interface{}) {
	log.Printf("saml: "+format, v...)
}

// SecurityOpts allows to bypass some security checks.
type SecurityOpts struct {
	AllowSelfSignedCert   bool
	TrustUnknownAuthority bool
}

// IsSecurityException returns whether the given error is a security exception
// not bypassed by SecurityOpts.
func IsSecurityException(err error, opts *SecurityOpts) bool {
	if _, ok := err.(xmlsec.ErrSelfSignedCertificate); ok {
		if opts.AllowSelfSignedCert {
			return false
		}
	}
	if _, ok := err.(xmlsec.ErrUnknownIssuer); ok {
		if opts.TrustUnknownAuthority {
			return false
		}
	}
	return true
}
