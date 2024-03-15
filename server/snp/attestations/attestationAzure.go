package attestations

import (
	"encoding/json"

	snp "snp/common"
	snp_util "snp/server/snp/snputil"

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

	str := []byte("")
	err = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: str,
		},
	})

	quote, err := stream.Recv()

	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "unable to receive quote: %v", err)
	}

	quotePayload := quote.GetChallengeResponse()

	quoteData := &snp.QuoteData{}

	if err = json.Unmarshal(quotePayload, quoteData); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to unmarshal quote response: %v", err)
	}

	checkQuote, err := snp_util.ValidateQuote(attestation.TPMCert, quoteData.Quote, quoteData.Sig, nonce)

	if !checkQuote {
		return nil, nil, status.Error(codes.InvalidArgument, "unable to check quote:")
	}

	valid := snp_util.ValidateAKGuestReport(&attestation.RuntimeData, &attestation.TPMCert)
	if !valid {
		return nil, nil, status.Errorf(codes.Internal, "unable to validate guest report against ak: %v", err)
	}

	return attestation.Report, attestation.Cert, err
}