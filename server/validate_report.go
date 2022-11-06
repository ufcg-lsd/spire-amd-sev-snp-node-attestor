package main

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"unsafe"
)

const SIGNATURE_OFFSET = 672
const SIGNATURE_LENGTH = int(unsafe.Sizeof(Signature{}))
const REPORT_LENGTH = int(unsafe.Sizeof(AttestationReport{}))

func ValidateGuestReportAgainstVCEK(report *[]byte, vcek *[]byte) bool {
	pubKey := getECDSAPubKeyFromByteArray(vcek)

	reportSplitted, signature := splitReportFromSignature(report)

	digest := getReportDigest(reportSplitted)

	valid := ecdsa.VerifyASN1(pubKey, digest[:], signature)

	return valid
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

	// Must revert bytes because they are in a bigEndian
	r := revertBytes(sig[:len(sig)/2])
	s := revertBytes(sig[len(sig)/2:])

	return reportWithoutSig, append(r, s...)
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
