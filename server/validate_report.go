package main

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

func ValidateGuestReport(vcek *[]byte, report *[]byte) bool {
	block, _ := pem.Decode([]byte(*vcek))
	cert, _ := x509.ParseCertificate(block.Bytes)
	pub := cert.PublicKey.(*ecdsa.PublicKey)

	reportWithoutSig := (*report)[0:672]
	sig := (*report)[672 : 1184-(512-144)]

	r := new(big.Int)
	r.SetBytes(revertBytes(sig[:len(sig)/2]))

	s := new(big.Int)
	s.SetBytes(revertBytes(sig[len(sig)/2:]))

	digest := make([]byte, 64)
	sum := sha512.Sum384(reportWithoutSig)
	copy(digest, sum[:])

	valid := ecdsa.Verify(pub, digest[:], r, s)

	return valid
}

func revertBytes(bytes []byte) []byte {
	for i := 0; i < len(bytes)/2; i++ {
		j := len(bytes) - i - 1
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes
}
