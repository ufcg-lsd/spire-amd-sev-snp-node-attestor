package attestations

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	snputil "snp/agent/snp/snputil"
	snp "snp/common"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AttestAzure struct{}

func (a *AttestAzure) GetAttestationData(stream nodeattestorv1.NodeAttestor_AidAttestationServer, ekPath string) error {
	rwc, err := snputil.GetTPM()
	if err != nil {
		return status.Errorf(codes.Internal, "can't open TPM at /dev/tpm0: %v", err)
	}
	defer rwc.Close()

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte("Azure"),
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to send attestation data: %v", err)
	}

	challenge, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to receive challenges: %v", err)
	}

	nonce := sha256.Sum256(challenge.Challenge)

	snpReport, tpmReport, err := snputil.GetReportFromTPM(rwc, snputil.AzureSNPReportIndex)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get report: %v", err)
	}

	var snpEK []byte
	if ekPath == "" {
		snpEK, err = snputil.GetVCEKFromAMD(snp.BuildExpandedAttestationReport(snpReport))
	} else {
		snpEK, err = os.ReadFile(ekPath)
	}

	if err != nil {
		return status.Errorf(codes.Internal, "Error: %v", err)
	}

	akPublicBlob, err := snputil.GetAK(rwc)

	if err != nil {
		return status.Errorf(codes.Internal, "error trying to get AK: %v", err)
	}

	runtimeData, err := snputil.GetRuntimeData(tpmReport)

	if err != nil {
		return status.Errorf(codes.Internal, "error fetching runtime data: %v", err)
	}

	attestationData, err := json.Marshal(snp.AttestationRequestAzure{
		Report:      snpReport,
		Cert:        snpEK,
		TPMAK:       akPublicBlob,
		RuntimeData: runtimeData,
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: attestationData,
		},
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to send challenge response: %s", err)
	}

	quote, sig, err := snputil.GetQuoteTPM(rwc, nonce)

	if err != nil {
		return status.Errorf(codes.Internal, "error fetching tpm quote: %v", err)
	}

	quoteData, err := json.Marshal(snp.QuoteData{
		Quote: quote,
		Sig:   sig,
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal quote data: %v", err)
	}
	_, err = stream.Recv()

	if err != nil {
		return status.Errorf(codes.Internal, "error receiving message: %v", err)
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: quoteData,
		},
	})

	return err
}
