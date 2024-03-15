package attestations

import (
	"bytes"
	"crypto/rand"
	"encoding/json"

	snp "snp/common"
	snp_util "snp/server/snp/snputil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AttestSVSM struct{}

func (a *AttestSVSM) GetAttestationData(stream nodeattestorv1.NodeAttestor_AttestServer) ([]byte, []byte, error) {
	err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: []byte(""),
		},
	})

	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "unable to send OK to Agent: %v", err)
	}

	req, err := stream.Recv()
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "failed to receive attestation request: %v", err)
	}

	attestationType := req.GetChallengeResponse()
	registration := &snp.RegistrationRequestSVSM{}

	if err = json.Unmarshal(attestationType, registration); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to unmarshal challenge response: %v", err)
	}


	DecEKPub, err := snp.DecodeEK(registration.TPMEK)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "Decode TPM EK failed: %v", err)
	}

	valid, err := snp_util.ValidateTPMEKFromReport(registration.Report, DecEKPub)

	if !valid {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to validate TPM EK hash from report: %v", err)
	}

	aikPub, err := tpm2.DecodePublic(registration.TPMAIK)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to decode public blob of AIK: %v", err)
	}
	aikPubName, err := aikPub.Name()
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to get AIK pub name: %v", err)
	}

	if aikPubName.Digest == nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "AIK digest is nil: %v", err)
	}

	credential := make([]byte, 16)
	rand.Read(credential)

	credBlob, encryptedSecret, err := credactivation.Generate(aikPubName.Digest, DecEKPub, 16, credential)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "makeCredential failed: %v", credBlob)
	}

	nonce := snp.GenerateNonce(uint8(16))

	attestationRequest := &snp.AttestationRequestSVSM{
		Challenge: snp.Challenge{
			CredBlob: credBlob[2:],
			Secret:   encryptedSecret[2:],
		},
		Nonce: nonce,
	}

	attestationRequestBytes, err := json.Marshal(attestationRequest)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to marshal TPM challenge: %v", credBlob)
	}

	_ = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: attestationRequestBytes,
		},
	})

	req, err = stream.Recv()
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to send challenge and nonce: %v", err)
	}

	attestationType = req.GetChallengeResponse()
	attestation := &snp.AttestationResponseSVSM{}

	if err = json.Unmarshal(attestationType, attestation); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to unmarshal attestation response: %v", err)
	}

	if !bytes.Equal(attestation.Secret, credential) {
		return nil, nil, status.Errorf(codes.Internal, "secret received doesn't match with the credential sent")
	}

	aik, _ := snp.ExtractRSAPublicKey(aikPub)
	encAIK := snp.EncodePublicKeyToPEM(aik)

	checkQuote, err := snp_util.ValidateQuote(encAIK, attestation.QuoteData.Quote, attestation.QuoteData.Sig, nonce)

	if !checkQuote {
		return nil, nil, status.Error(codes.InvalidArgument, "unable to check quote:")
	}

	return registration.Report, registration.Cert, err
}