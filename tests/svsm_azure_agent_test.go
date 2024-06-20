package snp_test

import (
	"context"
	"crypto/x509"
	"io"
	"os"
	"snp/agent/snp"
	tpm_util "snp/agent/snp/snputil"
	snpcommon "snp/common"
	snp_util "snp/server/snp/snputil"
	"strings"
	"testing"

	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupAzureSuite(t *testing.T) func() {
	setupCerts(t)
	// Create a new TPM simulator
	sim, err := NewTPMSim(tpm_util.AzureSNPReportIndex)
	require.NoError(t, err)

	/*
		Mock GetCRLByURL function to read it from file
	*/
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

	tpm_util.GetVCEKFromAMD = func(report snpcommon.AttestationReportExpanded) ([]byte, error) {
		return os.ReadFile(dir + "/keys/public/vcek/cert")
	}
	tpm_util.GetTPM = func() (io.ReadWriteCloser, error) {
		return sim.OpenTPM("/dev/tpmrm0")
	}

	snp.CheckEnv = func() string { return "AZURE" }

	return func() {
		clean(t)
		sim.Close()
	}
}

func TestAzureFlow(t *testing.T) {
	t.Cleanup(setupAzureSuite(t))

	testCases := []testCases{
		{
			name:      "successfull attestation with CRL verification",
			agentConf: `ek_path = "./keys/public/vcek/cert"`,
			serverConf: `
				cert_chains = ["./keys/public/vcek/cert_chain"]
				crl_urls = ["http://localhost:3000/vcek/crl"]
				insecure_crl = false
				min_fw_version = 0x08
				`,
			err: "",
		},
		{
			name:      "successfull attestation retrieving the vcek cert from http server",
			agentConf: ``,
			serverConf: `
				cert_chains = ["./keys/public/vcek/cert_chain"]
				crl_urls = ["http://localhost:3000/vcek/crl"]
				insecure_crl = false
				min_fw_version = 0x08
				`,
			err: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			agentPlugin := loadAgentPlugin(t, tc.agentConf)
			serverPlugin := loadServerPlugin(t, tc.serverConf)

			attribs, err := doAzureAttestationFlow(t, agentPlugin, serverPlugin)

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

func doAzureAttestationFlow(t *testing.T, agentPlugin agentnodeattestorv1.NodeAttestorClient, serverPlugin servernodeattestorv1.NodeAttestorClient) (*servernodeattestorv1.AgentAttributes, error) {
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

	// receive init attestation with AZURE indication
	agentResponse, err := agentStream.Recv()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to receive payload from agent plugin: %v", err)
	}
	require.Equal(t, "AZURE", string(agentResponse.GetPayload()), "agent must request an AZURE attestation")

	// receive init attestation with AZURE indication
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

		if err := agentStream.Send(&agentnodeattestorv1.Challenge{
			Challenge: serverResponse.GetChallenge(),
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to send challenge to agent plugin: %v", err)
		}

		agentResponse, err = agentStream.Recv()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to receive response from agent plugin: %v", err)
		}

		if err := serverStream.Send(&servernodeattestorv1.AttestRequest{
			Request: &servernodeattestorv1.AttestRequest_ChallengeResponse{
				ChallengeResponse: agentResponse.GetChallengeResponse(),
			},
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to send challenge reponse to server plugin: %v", err)
		}
	}
}
