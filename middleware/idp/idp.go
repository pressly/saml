// Package idp provides an IdP middleware useful for different tasks such as
// serving metatada, processing an assertion or initiating a login request
// against a SP.
package idp

import (
	"github.com/goware/saml"
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
