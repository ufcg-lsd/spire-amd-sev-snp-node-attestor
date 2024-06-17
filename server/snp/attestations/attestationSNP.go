package attestations

import (
	"crypto/sha512"
	"encoding/json"

	snp "snp/common"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AttestSNP struct{}

func (a *AttestSNP) GetAttestationData(stream nodeattestorv1.NodeAttestor_AttestServer) ([]byte, []byte, error) {
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

	attestation := &snp.AttestationDataRequest{}

	if err = json.Unmarshal(challengeResponse, attestation); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to unmarshal challenge response: %v", err)
	}

	report := snp.BuildExpandedAttestationReport(attestation.Report)

	sha512Nonce := sha512.Sum512(nonce)
	if report.ReportData != sha512Nonce {
		return nil, nil, status.Errorf(codes.Internal, "invalid nonce received in report: %v", err)
	}

	return attestation.Report, attestation.Cert, nil
}
