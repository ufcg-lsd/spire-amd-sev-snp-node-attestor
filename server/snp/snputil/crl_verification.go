package snp

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
)

var crlVcekCache *x509.RevocationList
var crlVlekCache *x509.RevocationList

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

func ObtainCRL(crlUrl string, crlCache **x509.RevocationList) (*x509.RevocationList, error){
	var crl *x509.RevocationList
	var err error

	crl, err = GetCRLByURL(crlUrl)
	if err != nil{
		if crlCache != nil{
			crl = *crlCache
			err = errors.New("warn using cache")
		} 
	} else {
		*crlCache = crl
	}

	return crl, err
}

func CheckRevocationList(ek []byte, caPath string, vcekCRLUrl string, vlekCRLUrl string, signingKey uint32) (error) {

	var crl *x509.RevocationList
	var err error
	var errFetchCRL error

	if signingKey == 0{
		crl, errFetchCRL = ObtainCRL(vcekCRLUrl, &crlVcekCache)	
	} else {
		crl, errFetchCRL = ObtainCRL(vlekCRLUrl, &crlVlekCache)
	}

	if crl == nil{ return errors.New("couldn't fetch CRL using the provided URL and cache is empty")}

	checkSignature, err := CheckCRLSignature(crl, caPath)
	if !checkSignature {
		return err
	}

	block, _ := pem.Decode(ek)
	if block == nil {
		return err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	serialNumber := cert.SerialNumber
	revoked := crl.RevokedCertificateEntries
	if revoked != nil {
		for i := len(revoked) - 1; i >= 0; i-- {
			revockedSerialNumber := revoked[i].SerialNumber
			if serialNumber.Cmp(revockedSerialNumber) == 0 {
				err = errors.New("the certificate is revoked")
				return err
			}
		}
	}
	
	return errFetchCRL
}
