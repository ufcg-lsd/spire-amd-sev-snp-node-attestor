package attestations

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"

	snp "snp/common"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)
type AttestSNP struct{}

func (a *AttestSNP) GetAttestationData(stream nodeattestorv1.NodeAttestor_AidAttestationServer, ekPath string) error{
	err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte("SNP"),
		},
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to send attestation data: %v", err)
	}

	challenge, err := stream.Recv()

	if err != nil {
		return status.Errorf(codes.Internal, "unable to receive challenges: %v", err)
	}

	nonce := sha512.Sum512(challenge.Challenge)

	device, err := client.OpenDevice()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to open device: %v", err)
	}

	defer device.Close()

	var certificateTable []byte
	var report []byte

	if ekPath == "" {
		report, certificateTable, err = client.GetRawExtendedReport(device, nonce)
	} else {
		report, err = client.GetRawReport(device, nonce)
	}

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get report: %v", err)
	}

	key, err := getChipKey(certificateTable, report, ekPath)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get ek: %v", err)
	}

	attestationData, err := json.Marshal(snp.AttestationDataRequest{
		Report: report,
		Cert:   key,
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

	return nil
}


func getChipKey(certificateTable []byte, report []byte, ekPath string) ([]byte, error) {

	var err error
	var ek []byte
	signingKey := snp.GetSigningKey(&report)


	if ekPath != "" {
		ek, err = os.ReadFile(ekPath)
		if err != nil {
			return nil, err
		}
	} else {
		certs := new(abi.CertTable)
		err := certs.Unmarshal(certificateTable)
		if err != nil {
			return nil, err
		}

		if signingKey == 0 {
			ek, err = certs.GetByGUIDString(abi.VcekGUID)

			if err != nil {
				return nil, err
			}
		} else {
			ek, _ = certs.GetByGUIDString(abi.VlekGUID)

			tmp, err := x509.ParseCertificate(ek)
			if err != nil {
				return nil, err
			}

			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: tmp.Raw,
			}

			ek = pem.EncodeToMemory(pemBlock)
		}
	}

	return ek, nil
}