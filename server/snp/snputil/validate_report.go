package snp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	snp "snp/common"
	"unsafe"

	"github.com/google/go-tpm/tpm2"
)

const SIGNATURE_OFFSET = 672
const SIGNATURE_LENGTH = int(unsafe.Sizeof(snp.Signature{}))
const REPORT_LENGTH = int(unsafe.Sizeof(snp.AttestationReport{}))

type ecdsaSignature struct {
	R, S *big.Int
}

//compare key used to sign/verify TPM quote with key that
//is included in SNP report

func ValidateGuestReportAgainstEK(report *[]byte, vcek *[]byte) bool {
	pubKey := getECDSAPubKeyFromByteArray(vcek)

	reportSplitted, signature := splitReportFromSignature(report)

	parsedSignature := parseECDSASignature(signature)

	digest := getReportDigest(reportSplitted)

	valid := ecdsa.Verify(pubKey, digest[:], parsedSignature.R, parsedSignature.S)

	return valid
}

func ValidateAKGuestReport(runtimeData *[]byte, ak *[]byte) bool {
	akString := string(*ak)
	runtimeAKString := getAKFromRuntimeData(*runtimeData)

	return akString == runtimeAKString
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

func ValidateQuoteWithAK(akPubPem []byte, quote []byte, sig *tpm2.Signature, nonce []byte) (bool, error) {
	hsh := crypto.SHA256.New()
	hsh.Write(quote)

	quoteInfo := getQuoteInfo(quote)
	valid, err := verifyNonce(nonce, quoteInfo.Nonce)
	if !valid {
		log.Printf("Error trying to verify nonce: %v", err)
		return false, err
	}

	rsaPubKey, err := getPublicKey(akPubPem)
	if err != nil {
		log.Printf("Error trying to get rsa public key: %v", err)
		return false, err
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hsh.Sum(nil), sig.RSA.Signature)
	if err != nil {
		log.Printf("Faild to verify tpm quote: %v", err)
		return false, err
	}

	log.Println("Quote successfully verified\n")
	return true, nil
}

func verifyNonce(nonce []byte, quoteNonce []byte) (bool, error) {
	shaNonce := sha256.Sum256(nonce)

	return bytes.Equal(shaNonce[:], quoteNonce), nil
}

func ValidateGuestReportSize(report *[]byte) error {
	var err error = nil

	if len((*report)) != REPORT_LENGTH {
		err = fmt.Errorf("invalid report length, expected: %d, but received: %d", REPORT_LENGTH, len((*report)))
	}

	return err
}

type QuoteInfo struct {
	Head  []byte
	Nonce []byte
	Quote []byte
}

func getQuoteInfo(quote []byte) QuoteInfo {
	var info QuoteInfo

	info.Head = quote[:44]
	info.Nonce = quote[44:76]
	info.Quote = quote[76:]

	return info
}

func getECDSAPubKeyFromByteArray(byteArray *[]byte) *ecdsa.PublicKey {
	block, _ := pem.Decode([]byte(*byteArray))
	cert, _ := x509.ParseCertificate(block.Bytes)
	pub := cert.PublicKey.(*ecdsa.PublicKey)

	return pub
}

func splitReportFromSignature(report *[]byte) ([]byte, []byte) {
	reportWithoutSig := (*report)[:SIGNATURE_OFFSET]
	sig := (*report)[SIGNATURE_OFFSET : REPORT_LENGTH-(SIGNATURE_LENGTH-144)]

	return reportWithoutSig, sig
}

func parseECDSASignature(sigBytes []byte) ecdsaSignature {
	r := new(big.Int)
	r.SetBytes(revertBytes(sigBytes[:len(sigBytes)/2]))

	s := new(big.Int)
	s.SetBytes(revertBytes(sigBytes[len(sigBytes)/2:]))

	return ecdsaSignature{
		R: r,
		S: s,
	}
}

func getReportDigest(report []byte) []byte {
	digest := make([]byte, 64)
	sum := sha512.Sum384(report)
	copy(digest, sum[:])

	return digest
}

func revertBytes(bytes []byte) []byte {
	for i := 0; i < len(bytes)/2; i++ {
		j := len(bytes) - i - 1
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes
}

func getPublicKey(akPubPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(akPubPem)
	if block == nil {
		log.Println("Error decoding PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Println("Error parsing RSA public key:", string(akPubPem))
		return nil, err
	}

	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		log.Println("A chave não é uma chave RSA pública")
		return nil, err
	}

	return rsaPubKey, nil
}
