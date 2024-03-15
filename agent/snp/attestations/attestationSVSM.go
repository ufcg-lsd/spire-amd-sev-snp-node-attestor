package attestations

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	snp "snp/common"
	snputil "snp/agent/snp/snputil"

	"github.com/google/go-tpm/tpm2"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AttestSVSM struct{}

func (a *AttestSVSM) GetAttestationData(stream nodeattestorv1.NodeAttestor_AidAttestationServer, ekPath string) error{
	rwc, err := snputil.GetTPM()
	if err != nil{
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

	key, err := os.ReadFile(ekPath)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get VCEK/VLEK: %v", err)
	}

	report, err := snputil.GetReportFromTPMSVSM(rwc)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get report: %v", err)
	}

	ek, err := snputil.GetTPMEK(rwc)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get TPM EK: %v", err)
	}

	cryptoKey, err := ek.Key()

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get TPM EK PublicKey: %v", err)
	}

	encodedEK, err := snp.EncodeEK(cryptoKey)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to encode TPM EK: %v", err)
	}

	aikHandle, aikPublicBlob, err := snputil.CreateTPMAIK(rwc)

	defer tpm2.FlushContext(rwc, aikHandle)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to create TPM AIK: %v", err)
	}

	registrationResponse, err := json.Marshal(snp.RegistrationRequestSVSM{
		Report: report,
		Cert:   key,
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
		return status.Errorf(codes.Internal, "unable to create auth session: %v", err)
	}

	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
	}

	if _, _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return status.Errorf(codes.Internal, "unable to create the policy secret: %v", err)
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
		aikHandle,
		snp.HandleEndorsement,
		attestationRequest.Challenge.CredBlob,
		attestationRequest.Challenge.Secret)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to ActivateCredentialUsingAuth: %v", err)
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

