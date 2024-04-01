package snp

import (
	"errors"
	"fmt"
	"io"
	snp "snp/common"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	AzureSNPReportIndex         tpmutil.Handle = 0x01400001
	TPMAkHandle                 tpmutil.Handle = 0x81000003
	TPMAuthHandle               tpmutil.Handle = 0x40000001
	SVSMOnPremiseSNPReportIndex tpmutil.Handle = 0x1C00002
	tpmEKHandle                 tpmutil.Handle = 0x81010001
	prefixZeros                 int16          = 32
)

func GetTPM() (io.ReadWriteCloser, error) {
	rwc, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return nil, err
	}

	return rwc, nil
}

func GetReportFromTPM(rwc io.ReadWriteCloser, reportIndex tpmutil.Handle) ([]byte, []byte, error) {
	var tpmReport []byte
	var snpReport []byte
	var err error

	if reportIndex == AzureSNPReportIndex {
		tpmReport, err = tpm2.NVReadEx(rwc, reportIndex, TPMAuthHandle, "", 0)
		snpReport = tpmReport[prefixZeros : prefixZeros+1184]
	} else {
		snpReport, err = tpm2.NVReadEx(rwc, reportIndex, TPMAuthHandle, "", 0)
	}

	return snpReport, tpmReport, err
}

func GetRuntimeData(initReport []byte) ([]byte, error) {
	// Data to be skipped in the report
	skipBytes := 1236

	runtimeDataSkip := initReport[skipBytes:]

	if len(runtimeDataSkip) <= skipBytes {
		return nil, errors.New("array too short")
	}

	var runtimeData []byte
	for _, byte := range runtimeDataSkip {
		if byte != 0x00 {
			runtimeData = append(runtimeData, byte)
		}
	}

	return runtimeData, nil
}

func GetQuoteTPM(rwc io.ReadWriteCloser, nonce [32]byte, handle tpmutil.Handle) ([]byte, *tpm2.Signature, error) {
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{4, 7}}

	quote, sig, err := tpm2.Quote(rwc, handle, "", "", nonce[:], pcrSelection, tpm2.AlgNull)
	if err != nil {
		fmt.Printf("Error to create quote: %v\n", err)
	}

	return quote, sig, err
}

func GetAK(rwc io.ReadWriteCloser, handle tpmutil.Handle) ([]byte, error) {
	ak, _, _, err := tpm2.ReadPublic(rwc, handle)
	if err != nil {
		return nil, err
	}

	rsaPubKey, err := snp.ExtractRSAPublicKey(ak)
	if err != nil {
		return nil, err
	}

	pemBytes := snp.EncodePublicKeyToPEM(rsaPubKey)

	return pemBytes, nil
}

func GetTPMEK(rwc io.ReadWriteCloser) (tpm2.Public, error) {
	ek, _, _, err := tpm2.ReadPublic(rwc, tpmEKHandle)

	if err != nil {
		return tpm2.Public{}, fmt.Errorf("tpm2.ReadPublic failed: %w", err)
	}

	tpm2.FlushContext(rwc, snp.HandleEndorsement)

	return ek, err
}

func CreateTPMAIK(rwc io.ReadWriteCloser) (tpmutil.Handle, []byte, error) {
	sessCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)

	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.StartAuthSession failed: %v", err)
	}

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{
			Session:    tpm2.HandlePasswordSession,
			Attributes: tpm2.AttrContinueSession,
		},
		sessCreateHandle, nil, nil, nil, 0)

	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.PolicySecret failed: %v", err)
	}

	authCommandCreateAuth := tpm2.AuthCommand{
		Session:    sessCreateHandle,
		Attributes: tpm2.AttrContinueSession,
	}

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKeyUsingAuth(
		rwc,
		tpmEKHandle,
		snp.PcrSelectionAll,
		authCommandCreateAuth,
		"",
		snp.AIKTemplate)

	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.CreateKeyUsingAuth failed: %v", err)
	}

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)

	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.StartAuthSession failed: %v", err)
	}

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{
			Session:    tpm2.HandlePasswordSession,
			Attributes: tpm2.AttrContinueSession,
		},
		loadCreateHandle, nil, nil, nil, 0)

	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.PolicySecret failed: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{
		Session:    loadCreateHandle,
		Attributes: tpm2.AttrContinueSession,
	}

	aikHandle, _, err := tpm2.LoadUsingAuth(rwc, tpmEKHandle, authCommandLoad, publicBlob, privateBlob)

	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.LoadUsingAuth failed: %v", err)
	}

	return aikHandle, publicBlob, nil
}

func VerifyAzure() bool {

	rwc, _ := GetTPM()
	defer rwc.Close()

	_, err := tpm2.NVReadEx(rwc, AzureSNPReportIndex, TPMAuthHandle, "", 0)
	return err == nil
}
