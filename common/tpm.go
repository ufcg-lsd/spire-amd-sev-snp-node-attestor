package snp

import (
	"github.com/google/go-tpm/tpm2"
)

type QuoteData struct {
	Quote []byte
	Sig   *tpm2.Signature
}
