package saml

import (
	"time"
)

func tearUp() {
	fakeNow := time.Now()

	Now = func() time.Time {
		return fakeNow
	}

	NewID = func() string {
		return "id-MOCKID"
	}
}
