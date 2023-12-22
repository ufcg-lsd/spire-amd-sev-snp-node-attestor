package snp

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func GetReportTPM() ([]byte, []byte, error) {
	rwc := GetTPM().rwc

	var snpReportIndex tpmutil.Handle = 0x01400001

	var tpmAuthHandle tpmutil.Handle = 0x40000001

	initReport, err := tpm2.NVReadEx(rwc, snpReportIndex, tpmAuthHandle, "", 0)
	if err != nil {
		fmt.Errorf("Error reading nv index: ", err)
	}

	reportBin := initReport[32 : 32+1184]

	return reportBin, initReport, nil
}

func GetRuntimeData(initReport []byte) ([]byte, error) {
	// Data to be skipped in the report
	skipBytes := 1236

	runtimeDataSkip := initReport[skipBytes:]

	if len(runtimeDataSkip) <= skipBytes {
		fmt.Println("Array too short.")
	}

	var runtimeData []byte
	for _, b := range runtimeDataSkip {
		if b != 0x00 {
			runtimeData = append(runtimeData, b)
		}
	}

	return runtimeData, nil
}

func GetQuoteTPM(nonce [32]byte) ([]byte, *tpm2.Signature, error) {
	rwc := GetTPM().rwc

	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{4, 7}}

	var tpmAkHandle tpmutil.Handle = 0x81000003

	quote, sig, err := tpm2.Quote(rwc, tpmAkHandle, "", "", nonce[:], pcrSelection, tpm2.AlgNull)
	if err != nil {
		fmt.Printf("Error to create quote: %v\n", err)
	}

	return quote, sig, err
}
