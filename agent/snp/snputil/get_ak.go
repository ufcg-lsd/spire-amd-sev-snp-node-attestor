package snp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func GetAK() ([]byte, error) {
	rwc := GetTPM().rwc

	var tpmAkHandle tpmutil.Handle = 0x81000003

	ak, _, _, err := tpm2.ReadPublic(rwc, tpmAkHandle)
	if err != nil {
		fmt.Errorf("error reading public part of AK:", err)
	}

	rsaPubKey, err := extractRSAPublicKey(ak)
	if err != nil {
		fmt.Errorf("error extracting AK RSA public key:", err)
	}

	pemBytes := encodePublicKeyToPEM(rsaPubKey)

	return pemBytes, nil
}

func extractRSAPublicKey(tpmPub tpm2.Public) (*rsa.PublicKey, error) {
	rsaPubKey, err := tpmPub.Key()
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := rsaPubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("The public key is not an RSA public key")
	}
	return rsaPublicKey, nil
}

func encodePublicKeyToPEM(pub *rsa.PublicKey) []byte {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return pemBytes
}
