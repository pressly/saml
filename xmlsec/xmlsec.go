// Package xmlsec is a wrapper around the xmlsec1 command
// https://www.aleksey.com/xmlsec/index.html
package xmlsec

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// ErrSelfSignedCertificate is a typed error returned when xmlsec1 detects a
// self-signed certificate.
type ErrSelfSignedCertificate struct {
	err error
}

// Error returns the underlying error reported by xmlsec1.
func (e ErrSelfSignedCertificate) Error() string {
	return e.err.Error()
}

// ErrUnknownIssuer is a typed error returned when xmlsec1 detects a
// "unknown issuer" error.
type ErrUnknownIssuer struct {
	err error
}

// Error returns the underlying error reported by xmlsec1.
func (e ErrUnknownIssuer) Error() string {
	return e.err.Error()
}

// Encrypt encrypts a byte sequence into an EncryptedData template using the
// given certificate and encryption method.
func Encrypt(template *EncryptedData, in []byte, publicCertPath string, method string) ([]byte, error) {
	// Writing template.
	fp, err := ioutil.TempFile("/tmp", "xmlsec")
	if err != nil {
		return nil, err
	}
	defer os.Remove(fp.Name())

	out, err := xml.MarshalIndent(template, "", "\t")
	if err != nil {
		return nil, err
	}
	_, err = fp.Write(out)
	if err != nil {
		return nil, err
	}
	if err := fp.Close(); err != nil {
		return nil, err
	}

	// Executing command.
	cmd := exec.Command("xmlsec1", "--encrypt",
		"--session-key", method,
		"--pubkey-cert-pem", publicCertPath,
		"--output", "/dev/stdout",
		"--xml-data", "/dev/stdin",
		fp.Name(),
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	outbr := bufio.NewReader(stdout)
	errbr := bufio.NewReader(stderr)

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if _, err := stdin.Write(in); err != nil {
		return nil, err
	}

	if err := stdin.Close(); err != nil {
		return nil, err
	}

	res, err := ioutil.ReadAll(outbr)
	if err != nil {
		return nil, err
	}

	resErr, err := ioutil.ReadAll(errbr)
	if err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		if len(resErr) > 0 {
			return res, xmlsecErr(string(resErr))
		}
		return nil, err
	}

	return res, nil
}

// Decrypt takes an encrypted XML document and decrypts it using the given
// private key.
func Decrypt(in []byte, privateKeyPath string) ([]byte, error) {
	// Executing command.
	cmd := exec.Command("xmlsec1", "--decrypt",
		"--privkey-pem", privateKeyPath,
		"--output", "/dev/stdout",
		"/dev/stdin",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	outbr := bufio.NewReader(stdout)
	errbr := bufio.NewReader(stderr)

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if _, err := stdin.Write(in); err != nil {
		return nil, err
	}

	if err := stdin.Close(); err != nil {
		return nil, err
	}

	res, err := ioutil.ReadAll(outbr)
	if err != nil {
		return nil, err
	}

	resErr, err := ioutil.ReadAll(errbr)
	if err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		if len(resErr) > 0 {
			return res, xmlsecErr(string(resErr))
		}
		return nil, err
	}

	return res, nil
}

// Verify takes a signed XML document and validates its signature.
func Verify(in []byte, publicCertPath string, id string) error {
	cmd := exec.Command("xmlsec1", "--verify",
		"--pubkey-cert-pem", publicCertPath,
		// Security: Don't ever use --enabled-reference-uris "local" value,
		// since it'd allow potential attackers to read local files using
		// <Reference URI="file:///etc/passwd"> hack!
		"--enabled-reference-uris", "empty,same-doc",
		"--id-attr:ID", id,
		"/dev/stdin",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	outbr := bufio.NewReader(stdout)
	errbr := bufio.NewReader(stderr)

	if err := cmd.Start(); err != nil {
		return err
	}

	if _, err := stdin.Write(in); err != nil {
		return err
	}

	if err := stdin.Close(); err != nil {
		return err
	}

	res, err := ioutil.ReadAll(outbr)
	if err != nil {
		return err
	}

	resErr, err := ioutil.ReadAll(errbr)
	if err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {

		if len(resErr) > 0 {
			return xmlsecErr(string(res) + "\n" + string(resErr))
		}
		return err
	}

	return nil
}

// Sign takes a XML document and produces a signature.
func Sign(in []byte, privateKeyPath string, id string) (out []byte, err error) {
	cmd := exec.Command("xmlsec1",
		"--sign",
		"--privkey-pem", privateKeyPath,
		"--enabled-reference-uris", "empty,same-doc",
		"--id-attr:ID", id,
		"--output", "/dev/stdout",
		"/dev/stdin",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	outbr := bufio.NewReader(stdout)
	errbr := bufio.NewReader(stderr)

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if _, err := stdin.Write(in); err != nil {
		return nil, err
	}

	if err := stdin.Close(); err != nil {
		return nil, err
	}

	res, err := ioutil.ReadAll(outbr)
	if err != nil {
		return nil, err
	}

	resErr, err := ioutil.ReadAll(errbr)
	if err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		if len(resErr) > 0 {
			return res, xmlsecErr(string(resErr))
		}

		return nil, err
	}

	return res, nil
}

func xmlsecErr(s string) error {
	err := fmt.Errorf("xmlsec: %s", strings.TrimSpace(s))
	if strings.HasPrefix(s, "OK") {
		return nil
	}
	if strings.Contains(err.Error(), "signature failed") {
		return err
	}
	if strings.Contains(err.Error(), "msg=self signed certificate") {
		return ErrSelfSignedCertificate{err}
	}
	if strings.Contains(err.Error(), "msg=unable to get local issuer certificate") {
		return ErrUnknownIssuer{err}
	}
	return err
}
