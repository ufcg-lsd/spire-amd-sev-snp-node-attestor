package snp

import (
	"errors"
	"fmt"
	"io"
	snp "snp/common"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	AzureSNPReportIndex         tpmutil.Handle = 0x01400001
	TPMAKHandle                 tpmutil.Handle = 0x81000003
	TPMAuthHandle               tpmutil.Handle = 0x40000001
	TPMEKHandle                 tpmutil.Handle = 0x81010001
	SVSMOnPremiseSNPReportIndex tpmutil.Handle = 0x1C00002
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

func GetQuoteTPM(rwc io.ReadWriteCloser, nonce [32]byte) ([]byte, *tpm2.Signature, error) {
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{4, 7}}

	quote, sig, err := tpm2.Quote(rwc, TPMAKHandle, "", "", nonce[:], pcrSelection, tpm2.AlgNull)
	if err != nil {
		fmt.Printf("Error to create quote: %v\n", err)
	}

	return quote, sig, err
}

func GetAK(rwc io.ReadWriteCloser) ([]byte, error) {

	ak, _, _, err := tpm2.ReadPublic(rwc, TPMAKHandle)
	if err != nil {
		return []byte{}, err
	}

	akBlob, err := ak.Encode()

	if err != nil {
		return []byte{}, err
	}

	return akBlob, nil
}

func GetTPMEK(rwc io.ReadWriteCloser) (tpm2.Public, error) {
	ek, _, _, err := tpm2.ReadPublic(rwc, TPMEKHandle)

	if err != nil {
		return tpm2.Public{}, fmt.Errorf("tpm2.ReadPublic failed: %w", err)
	}

	tpm2.FlushContext(rwc, snp.HandleEndorsement)

	return ek, err
}

func CreateTPMAK(rwc io.ReadWriteCloser) ([]byte, error) {

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
		return nil, fmt.Errorf("tpm2.StartAuthSession failed: %v", err)
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
		return nil, fmt.Errorf("tpm2.PolicySecret failed: %v", err)
	}

	authCommandCreateAuth := tpm2.AuthCommand{
		Session:    sessCreateHandle,
		Attributes: tpm2.AttrContinueSession,
	}

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKeyUsingAuth(
		rwc,
		TPMEKHandle,
		snp.PcrSelectionAll,
		authCommandCreateAuth,
		"",
		snp.AKTemplate)

	if err != nil {
		return nil, fmt.Errorf("tpm2.CreateKeyUsingAuth failed: %v", err)
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
		return nil, fmt.Errorf("tpm2.StartAuthSession failed: %v", err)
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
		return nil, fmt.Errorf("tpm2.PolicySecret failed: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{
		Session:    loadCreateHandle,
		Attributes: tpm2.AttrContinueSession,
	}

	akHandle, _, err := tpm2.LoadUsingAuth(rwc, TPMEKHandle, authCommandLoad, publicBlob, privateBlob)

	if err != nil {
		return nil, fmt.Errorf("tpm2.LoadUsingAuth failed: %v", err)
	}

	err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, akHandle, TPMAKHandle)

	if err != nil {
		return nil, fmt.Errorf("tpm2.EvictControl failed: %v", err)
	}

	return publicBlob, nil
}

func GetChallengeSecret(rwc io.ReadWriteCloser, attestationRequest *snp.AttestationRequestSVSM) ([]byte, error) {

	session, _, err := tpm2.StartAuthSession(rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)

	defer tpm2.FlushContext(rwc, session)

	if err != nil {
		return nil, fmt.Errorf("tpm2.StartAuthSession failed: %v", err)
	}

	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
	}

	if _, _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("tpm2.PolicySecret failed: %v", err)
	}

	auths := []tpm2.AuthCommand{
		auth,
		{
			Session:    session,
			Attributes: tpm2.AttrContinueSession,
		},
	}

	secret, err := tpm2.ActivateCredentialUsingAuth(
		rwc,
		auths,
		TPMAKHandle,
		snp.HandleEndorsement,
		attestationRequest.Challenge.CredBlob,
		attestationRequest.Challenge.Secret)

	if err != nil {
		return nil, fmt.Errorf("tpm2.ActivateCredentialUsingAuth failed: %v", err)
	}

	return secret, nil
}

func VerifyAzure() bool {

	rwc, _ := GetTPM()
	defer rwc.Close()

	_, err := tpm2.NVReadEx(rwc, AzureSNPReportIndex, TPMAuthHandle, "", 0)
	return err == nil
}

func FlushContextAll(rwc io.ReadWriteCloser, handleType tpm2.HandleType) error {

	handles, _ := client.Handles(rwc, handleType)

	for _, handle := range handles {

		err := tpm2.FlushContext(rwc, tpmutil.Handle(handle))

		if err != nil {
			return fmt.Errorf("tpm2.FlushContext failed: %v", err)
		}
	}
	return nil
}
