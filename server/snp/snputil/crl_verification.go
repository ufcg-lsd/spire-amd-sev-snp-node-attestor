package snp

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
)

func CheckCRLSignature(crl *x509.RevocationList, caPath string) (bool, error) {
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return false, err
	}

	var askBlock *pem.Block
	for {
		block, rest := pem.Decode(caBytes)
		if block == nil {
			break
		}
		askBlock = block
		caBytes = rest
	}

	ca, err := x509.ParseCertificate(askBlock.Bytes)
	if err != nil {
		return false, err
	}

	err = crl.CheckSignatureFrom(ca)
	if err != nil {
		err = errors.New("CRL signature verification failed")
		return false, err
	}

	return true, err
}

func GetCRLByPath(crlPath string) (*x509.RevocationList, error) {
	crlData, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlData)
	if err != nil {
		return nil, err
	}

	return crl, err
}

func GetCRLByURL(crlUrl string) (*x509.RevocationList, error) {
	resp, err := http.Get(crlUrl)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(data)
	return crl, err
}

func CheckRevocationList(ek []byte, caPath string, crlPath string, crlUrl string, crlPriority string, defaultBehavior string) (bool, error) {

	var crl *x509.RevocationList
	var err error
	if crlPriority == "url" {
		crl, err = GetCRLByURL(crlUrl)
	} else {
		crl, err = GetCRLByPath(crlPath)
	}

	if err != nil && crlPriority == "url" && defaultBehavior == "continue" {
		err = errors.New("fetch CRL error")
		return false, err
	} else {
		if err != nil {
			return false, err
		}

		checkSignature, err := CheckCRLSignature(crl, caPath)
		if !checkSignature {
			return false, err
		}

		block, _ := pem.Decode(ek)
		if block == nil {
			return false, err
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false, err
		}

		serialNumber := cert.SerialNumber
		revoked := crl.RevokedCertificateEntries
		if revoked != nil {
			for i := len(revoked) - 1; i >= 0; i-- {
				revockedSerialNumber := revoked[i].SerialNumber
				if serialNumber.Cmp(revockedSerialNumber) == 0 {
					err = errors.New("the certificate is revoked")
					return false, err
				}
			}
		}
	}
	return true, err
}
