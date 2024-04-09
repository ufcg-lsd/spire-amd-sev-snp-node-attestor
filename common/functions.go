package snp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

func GenerateNonce(length uint8) []byte {
	nonce := make([]byte, length)
	rand.Read(nonce)

	return nonce
}

func GetSigningKey(report *[]byte) uint32 {
	reportStruct := BuildExpandedAttestationReport(*report)

	return reportStruct.Flags.SIGNING_KEY
}

func ExtractRSAPublicKey(tpmPub tpm2.Public) (*rsa.PublicKey, error) {
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

func EncodePublicKeyToPEM(pub *rsa.PublicKey) ([]byte, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return pemBytes, nil
}

func EncodeEK(pub crypto.PublicKey) ([]byte, error) {

	data, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("error marshaling ek public key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}), nil
}

func DecodeEK(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)

	if block == nil {
		return nil, errors.New("invalid pemBytes")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing ecdsa public key: %v", err)
	}

	return pub, nil
}

func ParseMagicNumber(public tpm2.Public) []byte {

	ek_pub, _ := public.Encode()

	newArray := make([]byte, len(ek_pub)+2)

	copy(newArray[2:], ek_pub)

	// add magic number for EK
	newArray[0] = 1
	newArray[1] = 58

	return newArray
}
