package saml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"
)

var (
	certCache = map[string]*x509.Certificate{}
	certMu    sync.RWMutex
)

func retriveCertificate(file string) (cert *x509.Certificate, err error) {
	certMu.RLock()
	if certCache[file] != nil {
		cert = certCache[file]
	}
	certMu.RUnlock()

	if cert != nil {
		return cert, nil
	}

	fp, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	buf, err := ioutil.ReadAll(fp)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode certificate (%v).", file)
	}

	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, err
}

func validateKeyFile(file string, err error) (string, error) {
	if err != nil {
		return "", err
	}

	cert, err := retriveCertificate(file)
	if err != nil {
		return "", fmt.Errorf("Failed to read certificate (%v): %v", file, err)
	}

	now := time.Now()

	if now.Before(cert.NotBefore) {
		return "", fmt.Errorf("cert is not valid before %v", cert.NotBefore)
	}

	if now.After(cert.NotAfter) {
		return "", fmt.Errorf("cert is not valid after %v", cert.NotAfter)
	}

	certMu.Lock()
	// Cache only a valid cert
	certCache[file] = cert
	certMu.Unlock()

	return file, err
}
