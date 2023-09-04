package snp

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	snp "snp/common"
	"unsafe"
)

const SIGNATURE_OFFSET = 672
const SIGNATURE_LENGTH = int(unsafe.Sizeof(snp.Signature{}))
const REPORT_LENGTH = int(unsafe.Sizeof(snp.AttestationReport{}))

type ecdsaSignature struct {
	R, S *big.Int
}

func ValidateGuestReportAgainstEK(report *[]byte, vcek *[]byte) bool {
	pubKey := getECDSAPubKeyFromByteArray(vcek)

	reportSplitted, signature := splitReportFromSignature(report)

	parsedSignature := parseECDSASignature(signature)

	digest := getReportDigest(reportSplitted)

	valid := ecdsa.Verify(pubKey, digest[:], parsedSignature.R, parsedSignature.S)

	return valid
}

func ValidateGuestReportSize(report *[]byte) error {
	var err error = nil

	if len((*report)) != REPORT_LENGTH {
		err = fmt.Errorf("invalid report length, expected: %d, but received: %d", REPORT_LENGTH, len((*report)))
	}

	return err
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
