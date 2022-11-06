package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

func ValidateVCEKCertChain(vcek []byte, rootPath string) (bool, error) {
	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return false, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return false, err
	}

	block, _ := pem.Decode([]byte(vcek))
	if block == nil {
		return false, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return false, err
	}

	return true, nil
}
