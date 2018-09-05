package saml

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/goware/saml/xmlsec"
)

const defaultValidDuration = time.Hour * 24 * 2

// IssueLifetime is the maximum timeframe where an assertion can be considered
// valid by the receptor.
const IssueLifetime = time.Second * 90

// ClockDriftTolerance is added or substracted to the current time to give some
// tolerance to assertion's NotBefore and NotOnOrAfter
var ClockDriftTolerance = time.Duration(0)

// Now is a function that returns the current time. This value can be
// overwritten during tests.
var Now = time.Now

// NewID is a function that returns a unique identifier. This value can be
// overwritten during tests.
var NewID = func() string {
	uid, _ := uuid.NewV4()
	return fmt.Sprintf("id-%x", uid)
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

func GetAssertionFromCtx(ctx context.Context) *Assertion {
	return ctx.Value("saml.assertion").(*Assertion)
}
