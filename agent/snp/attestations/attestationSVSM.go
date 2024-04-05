package attestations

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	snputil "snp/agent/snp/snputil"
	snp "snp/common"

	"github.com/google/go-tpm/tpmutil"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AttestSVSM struct{}

func (a *AttestSVSM) GetAttestationData(stream nodeattestorv1.NodeAttestor_AidAttestationServer, ekPath string) error {
	rwc, err := snputil.GetTPM()
	if err != nil {
		return status.Errorf(codes.Internal, "can't open TPM at /dev/tpm0: %v", err)
	}
	defer rwc.Close()

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte("SVSM"),
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to send attestation data: %v", err)
	}

	_, err = stream.Recv()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to receive challenges: %v", err)
	}

	snpReport, _, err := snputil.GetReportFromTPM(rwc, snputil.SVSMOnPremiseSNPReportIndex)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get report: %v", err)
	}

	tpmEK, err := snputil.GetTPMEK(rwc)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get TPM EK: %v", err)
	}

	cryptoKey, err := tpmEK.Key()

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get TPM EK PublicKey: %v", err)
	}

	encodedEK, err := snp.EncodeEK(cryptoKey)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to encode TPM EK: %v", err)
	}

	var aikPublicBlob []byte
	var aikHandle tpmutil.Handle

	aikHandle, aikPublicBlob, err = snputil.GetAIK(rwc)

	if err != nil {
		aikHandle, aikPublicBlob, err = snputil.CreateTPMAIK(rwc)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to create TPM AIK: %v", err)
		}
	}

	var snpEK []byte
	if ekPath == "" {
		snpEK, err = snputil.GetVCEKFromAMD(snp.BuildExpandedAttestationReport(snpReport))
	} else {
		snpEK, err = os.ReadFile(ekPath)
	}
	if err != nil {
		return status.Errorf(codes.Internal, "unable to get VCEK/VLEK: %v", err)
	}

	registrationResponse, err := json.Marshal(snp.RegistrationRequestSVSM{
		Report: snpReport,
		Cert:   snpEK,
		TPMEK:  encodedEK,
		TPMAIK: aikPublicBlob,
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal registration request: %v", err)
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: registrationResponse,
		},
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to send registration data: %v", err)
	}

	resp, err := stream.Recv()

	if err != nil {
		return status.Errorf(codes.Internal, "unable to receive challenge and nonce: %v", err)
	}

	attestationRequest := new(snp.AttestationRequestSVSM)

	if err := json.Unmarshal(resp.Challenge, attestationRequest); err != nil {
		return status.Errorf(codes.Internal, "unable to unmarshal attestation request: %v", err)
	}

	secret, err := snputil.GetChallengeSecret(rwc, attestationRequest, aikHandle)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get secret from challenge: %v", err)
	}

	nonce := sha256.Sum256(attestationRequest.Nonce)

	quote, sig, err := snputil.GetQuoteTPM(rwc, nonce, aikHandle)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create Quote: %v", err)
	}

	attestationResponse, err := json.Marshal(snp.AttestationResponseSVSM{
		QuoteData: snp.QuoteData{
			Quote: quote,
			Sig:   sig,
		},
		Secret: secret,
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal quote data: %v", err)
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: attestationResponse,
		},
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to send recoveredCredential data: %v", err)
	}

	return nil

}
