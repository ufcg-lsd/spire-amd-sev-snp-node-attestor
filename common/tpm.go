package snp

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const HandleEndorsement tpmutil.Handle = 0x81010001

var (
	AIKTemplate tpm2.Public = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
	PcrSelection7   = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7}}
	PcrSelectionAll = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 10}}
	PcrSelection10  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{10}}
)

type Challenge struct {
	CredBlob []byte
	Secret   []byte
}

type QuoteData struct {
	Quote []byte
	Sig   *tpm2.Signature
}
