package snp

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"path"
	snp "snp/common"
	snp_util "snp/server/snp/snputil"
	"sync"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger       = (*Plugin)(nil)
	_ pluginsdk.NeedsHostServices = (*Plugin)(nil)
)

const (
	pluginName = "sev_snp"
)

type Config struct {
	trustDomain  spiffeid.TrustDomain
	AMDCertChain string `hcl:"amd_cert_chain"`
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

func generateNonce(length uint8) []byte {
	nonce := make([]byte, length)
	rand.Read(nonce)

	return nonce
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	vcek := req.GetPayload()

	valid, err := snp_util.ValidateVCEKCertChain(vcek, config.AMDCertChain)
	if !valid {
		return err
	}

	nonce := generateNonce(uint8(16))

	stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: nonce,
		},
	})

	challengeRes, _ := stream.Recv()

	reportBytes := challengeRes.GetChallengeResponse()

	valid = snp_util.ValidateGuestReportAgainstVCEK(&reportBytes, &vcek)
	if !valid {
		return errors.New("unable to validate guest report against vcek")
	}

	report := snp_util.BuildAttestationReport(reportBytes)

	sha512Nonce := sha512.Sum512(nonce)
	if report.ReportData != sha512Nonce {
		return errors.New("invalid nonce received in report")
	}

	var spiffeID string
	var selectors []string

	spiffeID = AgentID(pluginName, config.trustDomain.String(), report)
	selectors = buildSelectorValues(report, vcek)

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       spiffeID,
				SelectorValues: selectors,
				CanReattest:    false,
			},
		},
	})
}

func AgentID(pluginName, trustDomain string, report snp.AttestationReport) string {
	measurement := report.Measurement[:10]

	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path: path.Join(
			"spire",
			"agent",
			pluginName,
			uuid.New().String(),
			"measurement",
			PrintByteArray(measurement[:]),
			"policy",
			fmt.Sprintf("0x%x", report.Policy),
		),
	}

	return u.String()
}

func PrintByteArray(array []byte) string {
	str := ""

	for i := 0; i < len(array); i++ {
		value := array[i]
		str += fmt.Sprintf("%02x", value)
	}

	return str
}

func buildSelectorValues(report snp.AttestationReport, vcek []byte) []string {
	selectorValues := []string{}

	sha512VCEK := sha512.Sum512(vcek)
	measurement := report.Measurement[:]
	policy := snp_util.BuildPolicy(report)

	selectorValues = append(selectorValues, "measurement:"+PrintByteArray(measurement[:]))
	selectorValues = append(selectorValues, "policy:"+fmt.Sprintf("0x%x", report.Policy))
	selectorValues = append(selectorValues, "policy:abi_minor:"+fmt.Sprintf("%d", policy.ABI_MINOR))
	selectorValues = append(selectorValues, "policy:abi_major:"+fmt.Sprintf("%d", policy.ABI_MAJOR))
	selectorValues = append(selectorValues, "policy:smt:"+fmt.Sprintf("%t", policy.SMT_ALLOWED))
	selectorValues = append(selectorValues, "policy:migrate_ma:"+fmt.Sprintf("%t", policy.MIGRATE_MA_ALLOWED))
	selectorValues = append(selectorValues, "policy:debug:"+fmt.Sprintf("%t", policy.DEBUG_ALLOWED))
	selectorValues = append(selectorValues, "policy:single_socket:"+fmt.Sprintf("%t", policy.SINGLE_SOCKET_ALLOWED))
	selectorValues = append(selectorValues, "vcek:"+PrintByteArray(sha512VCEK[:]))

	return selectorValues
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	trustDomain, err := parseCoreConfig(req.CoreConfiguration)
	if err != nil {
		return nil, err
	}

	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	config.trustDomain = trustDomain

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func parseCoreConfig(c *configv1.CoreConfiguration) (spiffeid.TrustDomain, error) {
	if c == nil {
		return spiffeid.TrustDomain{}, status.Error(codes.InvalidArgument, "core configuration is missing")
	}

	if c.TrustDomain == "" {
		return spiffeid.TrustDomain{}, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(c.TrustDomain)
	if err != nil {
		return spiffeid.TrustDomain{}, status.Errorf(codes.InvalidArgument, "trust_domain is invalid: %v", err)
	}

	return trustDomain, nil
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
