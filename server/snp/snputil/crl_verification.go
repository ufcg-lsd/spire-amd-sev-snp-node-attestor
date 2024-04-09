package snp

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

type CRLCacheEntry struct {
	crl        *x509.RevocationList
	url        string
	lastUpdate time.Time
}

type CRLCache struct {
	entries map[string]*CRLCacheEntry
	mutex   sync.RWMutex
}

var crlCache = CRLCache{
	entries: make(map[string]*CRLCacheEntry),
	mutex:   sync.RWMutex{},
}

func (crlCache *CRLCache) GetEntry(url string) *CRLCacheEntry {
	crlCache.mutex.Lock()
	crlCached := crlCache.entries[url]
	crlCache.mutex.Unlock()

	return crlCached
}

func (crlCache *CRLCache) AddEntry(url string, crl *x509.RevocationList) {
	crlCache.mutex.Lock()
	crlCache.entries[url] = &CRLCacheEntry{
		crl:        crl,
		url:        url,
		lastUpdate: time.Now(),
	}
	crlCache.mutex.Unlock()
}

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

func ObtainCRL(crlUrl string) (*x509.RevocationList, error) {
	var crl *x509.RevocationList
	var err error

	crlCached := crlCache.GetEntry(crlUrl)

	if crlCached == nil || time.Since(crlCached.lastUpdate) > 15*time.Minute {
		crl, err = GetCRLByURL(crlUrl)
		crlCache.AddEntry(crlUrl, crl)
	} else {
		crl = crlCached.crl
	}

	return crl, err
}

func IsCertRevoked(ek []byte, caPath string, CRLUrl string) (bool, error) {
	var crl *x509.RevocationList
	var err error
	isRevoked := false

	crl, _ = ObtainCRL(CRLUrl)

	if crl == nil {
		return isRevoked, errors.New("couldn't fetch CRL using the provided URL and cache is empty")
	}

	checkSignature, err := CheckCRLSignature(crl, caPath)
	if !checkSignature {
		return isRevoked, nil
	}

	block, _ := pem.Decode(ek)
	if block == nil {
		return isRevoked, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return isRevoked, err
	}

	serialNumber := cert.SerialNumber
	revoked := crl.RevokedCertificateEntries
	if revoked != nil {
		for i := len(revoked) - 1; i >= 0; i-- {
			revockedSerialNumber := revoked[i].SerialNumber
			if serialNumber.Cmp(revockedSerialNumber) == 0 {
				isRevoked = true
				return isRevoked, err
			}
		}
	}

	return isRevoked, err
}
