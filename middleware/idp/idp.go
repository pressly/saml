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

// Package idp provides an IdP middleware useful for different tasks such as
// serving metatada, processing an assertion or initiating a login request
// against a SP.
package idp

import (
	"github.com/pressly/saml"
	"net/http"
)

var redirectFormTemplate = `<!DOCTYPE html>
<html>
	<head></head>
	<body>
		<form id="redirect" method="POST" action="{{.FormAction}}">
			<input type="hidden" name="RelayState" value="{{.RelayState}}" />
			<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />
		</form>
		<script type="text/javascript">
			document.getElementById("redirect").submit();
		</script>
	</body>
</html>`

type redirectForm struct {
	FormAction   string
	RelayState   string
	SAMLResponse string
}

// Authenticator defines an authentication function that returns a
// *saml.Session value.
type Authenticator func(w http.ResponseWriter, r *http.Request) (*saml.Session, error)

func writeErr(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}
