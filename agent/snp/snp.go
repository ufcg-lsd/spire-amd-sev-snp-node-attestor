package snp

import (
	"context"
	"errors"
	"os"

	snp_attestation "snp/agent/snp/attestations"
	snputil "snp/agent/snp/snputil"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger       = (*Plugin)(nil)
	_ pluginsdk.NeedsHostServices = (*Plugin)(nil)
)

type Config struct {
	Ek string `hcl:"ek_path"`
}

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer
	configMtx sync.RWMutex
	config    *Config
	logger    hclog.Logger
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	return nil
}

var CheckEnv = checkEnv

func checkEnv() string {
	_, err := os.Stat("/dev/sev-guest")

	var env string

	if err == nil {
		env = "SNP"
	} else if snputil.VerifyAzure() {
		env = "AZURE"
	} else {
		env = "SVSM"
	}

	return env
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	var attestAgent snp_attestation.AttestationAgent
	env := CheckEnv()

	if env == "SNP" {
		attestAgent = &snp_attestation.AttestSNP{}
	} else if env == "AZURE" {
		attestAgent = &snp_attestation.AttestAzure{}
	} else if env == "SVSM" {
		attestAgent = &snp_attestation.AttestSVSM{}
	} else {
		return errors.New("not a known SEV-SNP environment")
	}

	return attestAgent.GetAttestationData(stream, p.config.Ek)
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}
