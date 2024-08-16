package attestations

import (
	"encoding/json"

	snp "snp/common"
	snp_util "snp/server/snp/snputil"

	"github.com/google/go-tpm/legacy/tpm2"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AttestAzure struct{}

func (a *AttestAzure) GetAttestationData(stream nodeattestorv1.NodeAttestor_AttestServer) ([]byte, []byte, error) {
	nonce := snp.GenerateNonce(uint8(16))

	err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: nonce,
		},
	})

	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "unable to send challenges: %v", err)
	}

	res, err := stream.Recv()

	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "unable to receive challenges response: %v", err)
	}

	challengeResponse := res.GetChallengeResponse()

	attestation := &snp.AttestationRequestAzure{}

	if err = json.Unmarshal(challengeResponse, attestation); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to unmarshal challenge response: %v", err)
	}

	quoteData := attestation.QuoteData

	akPub, err := tpm2.DecodePublic(attestation.TPMAK)

	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to decode public blob of AK: %v", err)
	}

	akPubRSA, err := snp.ExtractRSAPublicKey(akPub)

	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to extract RSA public key of AK: %v", err)
	}

	akPubPEM, err := snp.EncodePublicKeyToPEM(akPubRSA)

	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to convert AK RSA public key to PEM : %v", err)
	}

	checkQuote, err := snp_util.ValidateQuote(akPubPEM, quoteData.Quote, quoteData.Sig, nonce)

	if !checkQuote {
		return nil, nil, status.Error(codes.InvalidArgument, "unable to check quote:")
	}

	valid := snp_util.ValidateAKGuestReport(&attestation.RuntimeData, &akPubPEM, &attestation.Report)
	if !valid {
		return nil, nil, status.Errorf(codes.Internal, "unable to validate guest report against ak: %v", err)
	}

	return attestation.Report, attestation.Cert, err
}
