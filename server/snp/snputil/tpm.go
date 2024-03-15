package snp

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	snp "snp/common"

	"github.com/google/go-tpm/tpm2"
)

type QuoteInfo struct {
	Head  []byte
	Nonce []byte
	Quote []byte
}

func ValidateQuote(tpmPubPem []byte, quote []byte, sig *tpm2.Signature, nonce []byte) (bool, error) {
	hsh := crypto.SHA256.New()
	hsh.Write(quote)

	quoteInfo := getQuoteInfo(quote)
	valid, err := verifyNonce(nonce, quoteInfo.Nonce)
	if !valid {
		return false, fmt.Errorf("incompatible nonces : %w", err)
	}

	rsaPubKey, err := getPublicKey(tpmPubPem)
	if err != nil {
		return false, fmt.Errorf("can't get rsa public key: %w", err)
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hsh.Sum(nil), sig.RSA.Signature)
	if err != nil {
		return false, fmt.Errorf("can't verify tpm quote: %w", err)
	}
	return true, nil
}

func verifyNonce(nonce []byte, quoteNonce []byte) (bool, error) {
	shaNonce := sha256.Sum256(nonce)

	return bytes.Equal(shaNonce[:], quoteNonce), nil
}

func getAKFromRuntimeData(runtimeData []byte) string {
	jsonData := string(runtimeData)

	var keysData struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.Unmarshal([]byte(jsonData), &keysData); err != nil {
		log.Fatalf("Failed to Unmarshal JSON: %v", err)
	}

	var publicKey *rsa.PublicKey
	for _, key := range keysData.Keys {
		if key.Kid == "HCLAkPub" {
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				log.Fatalf("Failed decoding N value: %v", err)
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				log.Fatalf("Failed decoding E value: %v", err)
			}

			n := new(big.Int).SetBytes(nBytes)
			e := new(big.Int).SetBytes(eBytes)

			publicKey = &rsa.PublicKey{
				N: n,
				E: int(e.Int64()),
			}

			break
		}
	}

	if publicKey == nil {
		log.Fatal("HCLAkPub key not found in JSON")
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Failed to encode public key to PEM: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	pemString := string(pem.EncodeToMemory(pemBlock))
	return pemString
}

func getQuoteInfo(quote []byte) QuoteInfo {
	var info QuoteInfo

	info.Head = quote[:44]
	info.Nonce = quote[44:76]
	info.Quote = quote[76:]

	return info
}

func getPublicKey(akPubPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(akPubPem)
	if block == nil {
		return nil, fmt.Errorf("error decoding PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA public key: %w", err)
	}

	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("wrong key format (expected RSA public key)")
	}

	return rsaPubKey, nil
}

func ValidateTPMEKFromReport(report []byte, ek crypto.PublicKey) (bool, error) {

	hash := getEKHashFromReport(report)

	rsaEKPublicKey, ok := ek.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("provided public key is not an RSA public key")
	}

	EKPublic := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    uint16(rsaEKPublicKey.N.BitLen()),
			ModulusRaw: rsaEKPublicKey.N.Bytes(),
		},
	}

	ekhash2 := snp.ParseMagicNumber(EKPublic)
	hash2 := sha512.Sum512(ekhash2)

	if !bytes.Equal(hash, hash2[:]) {
		return false, fmt.Errorf("EK SHA512 HASH is different from that provided by the attestation report")
	}

	return true, nil
}

func ValidateAKGuestReport(runtimeData *[]byte, ak *[]byte) bool {
	akString := string(*ak)
	runtimeAKString := getAKFromRuntimeData(*runtimeData)

	return akString == runtimeAKString
}

func getEKHashFromReport(initReport []byte) []byte {

	skipBytes := 80

	ekSHA512 := initReport[skipBytes:144]

	return ekSHA512
}

