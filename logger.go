package saml

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// UserRequest represents a request submitted from an user.
type UserRequest struct {
	Context    context.Context
	RemoteAddr string
	Method     string
	RequestURI string
	Header     http.Header
	Form       string
	Body       string
}

// String returns a formatted log with the user request, useful for debugging.
func (ur UserRequest) String() string {
	lines := []string{}

	if ur.Context != nil {
		lines = append(lines, fmt.Sprintf("Context: %v", ur.Context))
	}

	lines = append(lines, fmt.Sprintf("Method: %s", ur.Method))
	lines = append(lines, fmt.Sprintf("RemoteAddr: %s", ur.RemoteAddr))
	lines = append(lines, fmt.Sprintf("RequestURI: %s", ur.RequestURI))
	lines = append(lines, fmt.Sprintf("Header: %#v", ur.Header))

	if ur.Form != "" {
		lines = append(lines, fmt.Sprintf("Form: %s", ur.Form))
	}

	if ur.Body != "" {
		lines = append(lines, fmt.Sprintf("Body: %s", ur.Body))
	}

	return strings.Join(lines, "\n")
}

var logger Logger = &simpleLogger{log.New(os.Stdout, "SAML: ", log.Flags())}

// simpleLogger implements a Logger that treats fatal errors as regular
// ones.
type simpleLogger struct {
	lg *log.Logger
}

// Fatalf satisfies Logger.
func (s *simpleLogger) Fatalf(f string, v ...interface{}) {
	s.lg.Printf(f, v...)
}

// Fatal satisfies Logger.
func (s *simpleLogger) Fatal(v ...interface{}) {
	s.lg.Print(v...)
}

// Printf satisfies Logger.
func (s *simpleLogger) Printf(f string, v ...interface{}) {
	s.lg.Printf(f, v...)
}

// Print satisfies Logger.
func (s *simpleLogger) Print(v ...interface{}) {
	s.lg.Print(v...)
}

// Logger provides methods for request logging and debugging.
type Logger interface {
	Printf(s string, v ...interface{})

	Print(v ...interface{})

	Fatalf(s string, v ...interface{})

	Fatal(v ...interface{})
}

// InspectRequest creates a *UserRequest from a *http.Request
func InspectRequest(r *http.Request) *UserRequest {
	if r == nil {
		return nil
	}

	var body []byte
	if r.Body != nil {
		var err error
		// Read body contents.
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			body = []byte(fmt.Sprintf("[%v]", err.Error()))
		} else {
			// Reset body to original state.
			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		}
	}

	return &UserRequest{
		Context:    r.Context(),
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		RequestURI: r.RequestURI,
		Header:     r.Header,
		Form:       r.Form.Encode(),
		Body:       string(body),
	}
}

// Log prints logging message, not necessarily an error.
func Log(v ...interface{}) {
	logger.Print(v...)
}

// Logf prints a formatted logging message, not necessarily an error.
func Logf(s string, v ...interface{}) {
	logger.Printf(s, v...)
}

// Fatal prints an error. This does not end the execution of the program.
func Fatal(v ...interface{}) {
	logger.Fatal(v...)
}

// Fatalf prints a formatted error. This does not end the execution of the
// program.
func Fatalf(s string, v ...interface{}) {
	logger.Fatalf(s, v...)
}

// SetLogger determines which logger to use.
func SetLogger(lg Logger) {
	logger = lg
}

var _ = Logger(&simpleLogger{})
