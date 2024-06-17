package snp_test

import (
	"context"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"snp/agent/snp"
	snp_util "snp/server/snp/snputil"

	snpmock "github.com/Daviiap/sev-guest_device_mock/src"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupSNPSuite(t *testing.T) func() {
	setupCerts(t)
	device_mock := snpmock.New()
	device_mock.Start()

	snp_util.GetCRLByURL = func(crlUrl string) (*x509.RevocationList, error) {
		var ek string
		if strings.Contains(crlUrl, "vcek") {
			ek = "vcek"
		} else if strings.Contains(crlUrl, "vlek") {
			ek = "vlek"
		}

		crlFile, _ := os.ReadFile(dir + "/keys/public/" + ek + "/crl")

		crl, _ := x509.ParseRevocationList(crlFile)

		return crl, nil
	}

	snp.CheckEnv = func() string { return "SNP" }

	return func() {
		clean(t)
		device_mock.Stop()
	}
}

func TestSEVGuestDeviceFlow(t *testing.T) {
	t.Cleanup(setupSNPSuite(t))

	testCases := []testCases{
		{
			name:      "successfull attestation with CRL verification",
			agentConf: ``,
			serverConf: `
				cert_chains = ["./keys/public/vlek/cert_chain"]
				crl_urls = ["http://localhost:3000/vlek/crl"]
				insecure_crl = false
				min_fw_version = 0x08
				`,
			err: "",
		},
		{
			name:      "successfull attestation with CRL verification and passing ek_path on agent config",
			agentConf: `ek_path = "./keys/public/vlek/cert"`,
			serverConf: `
				cert_chains = ["./keys/public/vlek/cert_chain"]
				crl_urls = ["http://localhost:3000/vlek/crl"]
				insecure_crl = false
				min_fw_version = 0x08
				`,
			err: "",
		},
		{
			name:      "successfull attestation with multiple cert_chains and CRLs",
			agentConf: ``,
			serverConf: `
				cert_chains = ["./keys/public/vlek/cert_chain", "./keys/public/vcek/cert_chain"]
				crl_urls = ["http://localhost:3000/vlek/crl", "http://localhost:3000/vcek/crl"]
				insecure_crl = false
				min_fw_version = 0x08
				`,
			err: "",
		},
		{
			name:      "successfull attestation without CRL verification",
			agentConf: ``,
			serverConf: `
				cert_chains = ["./keys/public/vlek/cert_chain"]
				insecure_crl = true
				min_fw_version = 0x08
				`,
			err: "",
		},
		{
			name:      "error on ek signature validation against cert_chain",
			agentConf: ``,
			serverConf: `
				cert_chains = ["./keys/public/vcek/cert_chain"]
				insecure_crl = true
				min_fw_version = 0x08
				`,
			err: `rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = InvalidArgument desc = unable to validate AMD EK with AMD cert chain: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "SEV-Milan"`,
		},
		{
			name:      "error when passing invalid ek on ek_path",
			agentConf: `ek_path = "./keys/public/vcek/cert"`,
			serverConf: `
				cert_chains = ["./keys/public/vlek/cert_chain", "./keys/public/vcek/cert_chain"]
				crl_urls = ["http://localhost:3000/vlek/crl", "http://localhost:3000/vcek/crl"]
				insecure_crl = false
				min_fw_version = 0x08
				`,
			err: `rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Internal desc = unable to validate guest report against AMD EK`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			agentPlugin := loadAgentPlugin(t, tc.agentConf)
			serverPlugin := loadServerPlugin(t, tc.serverConf)

			attribs, err := doSNPAttestationFlow(t, agentPlugin, serverPlugin)

			if tc.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, attribs)
		})
	}
}

func doSNPAttestationFlow(t *testing.T, agentPlugin agentnodeattestorv1.NodeAttestorClient, serverPlugin servernodeattestorv1.NodeAttestorClient) (*servernodeattestorv1.AgentAttributes, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer ctx.Done()
	defer cancel()

	agentStream, err := agentPlugin.AidAttestation(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Canceled, "failed opening agent AidAttestation stream: %v", err)
	}

	serverStream, err := serverPlugin.Attest(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Canceled, "failed opening server Attest stream: %v", err)
	}

	// init attestation
	agentResponse, err := agentStream.Recv()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to receive payload from agent plugin: %v", err)
	}
	require.Equal(t, "SNP", string(agentResponse.GetPayload()), "agent must request an SNP attestation")

	if err := serverStream.Send(&servernodeattestorv1.AttestRequest{
		Request: &servernodeattestorv1.AttestRequest_Payload{
			Payload: agentResponse.GetPayload(),
		},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send payload to server plugin: %v", err)
	}

	for {
		serverResponse, err := serverStream.Recv()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to receive response from server plugin: %v", err)
		}

		if attribs := serverResponse.GetAgentAttributes(); attribs != nil {
			return attribs, nil
		}

		require.NotEmpty(t, serverResponse.GetChallenge(), "server plugin responded with an empty challenge")

		if err := agentStream.Send(&agentnodeattestorv1.Challenge{
			Challenge: serverResponse.GetChallenge(),
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to send challenge to agent plugin: %v", err)
		}

		agentResp, err := agentStream.Recv()

		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to receive challenge response from agent plugin: %v", err)
		}

		require.Nil(t, agentResp.GetPayload(), "agent plugin responded with a payload instead of a challenge")
		require.NotEmpty(t, agentResp.GetChallengeResponse(), "agent plugin responded with an empty challenge response")

		attestationData := agentResp.GetChallengeResponse()

		if err := serverStream.Send(&servernodeattestorv1.AttestRequest{
			Request: &servernodeattestorv1.AttestRequest_ChallengeResponse{
				ChallengeResponse: attestationData,
			},
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to send challange response to server plugin: %v", err)
		}
	}
}
