package snp

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"

	"net/url"
	"path"
	"sync"

	snp "snp/common"
	snp_attestation "snp/server/snp/attestations"
	snp_util "snp/server/snp/snputil"

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
	pluginName = "amd_sev_snp"
)

type Config struct {
	trustDomain      spiffeid.TrustDomain
	VcekAMDCertChain string `hcl:"vcek_cert_chain"`
	VlekAMDCertChain string `hcl:"vlek_cert_chain"`
	VcekCRLUrl       string `hcl:"vcek_crl_url"`
	VlekCRLUrl       string `hcl:"vlek_crl_url"`
	InsecureCRL      bool   `hcl:"insecure_crl"`
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

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	
	config, err := p.getConfig()
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "not configured: %v", err)
	}

	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to receive attestation request: %v", err)
	}
	attestationType := req.GetPayload()

	var attestServer snp_attestation.AttestationServer
	if bytes.Equal(attestationType, []byte("Azure")) {
		attestServer = &snp_attestation.AttestAzure{}
	} else if bytes.Equal(attestationType, []byte("SVSM")) {
		attestServer = &snp_attestation.AttestSVSM{}
	} else {
		attestServer = &snp_attestation.AttestSNP{}
	}

	reportBytes, ek, err := attestServer.GetAttestationData(stream)  
	if err != nil {
		return err
	}

	err = snp_util.ValidateGuestReportSize(&reportBytes)
	if err != nil {
		return status.Errorf(codes.Internal, "invalid report size: %v", err)
	}

	signingKey := snp.GetSigningKey(&reportBytes)
	err = p.validadeEndorsmentKey(ek, signingKey, config)
	if err != nil {
		return err
	}

	err = p.crlVerification(ek, signingKey, config)
	if err != nil {
		return err
	}

	valid := snp_util.ValidateGuestReportAgainstEK(&reportBytes, &ek)
	if !valid {
		return status.Errorf(codes.Internal, "unable to validate guest report against AMD EK")
	}

	report := snp_util.BuildAttestationReport(reportBytes)

	var spiffeID string
	var selectors []string

	spiffeID = AgentID(pluginName, config.trustDomain.String(), report)
	selectors = buildSelectorValues(report, ek)
	err = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       spiffeID,
				SelectorValues: selectors,
				CanReattest:    true,
			},
		},
	})

	return err
}

func (p *Plugin) validadeEndorsmentKey(ek []byte, signingKey uint32, config *Config) error {
	var valid = false
	var err error
	if signingKey == 0 {
		valid, err = snp_util.ValidateEKCertChain(ek, config.VcekAMDCertChain)
	} else {
		valid, err = snp_util.ValidateEKCertChain(ek, config.VlekAMDCertChain)
	}
	if !valid {
		return status.Errorf(codes.InvalidArgument, "unable to validate AMD EK with AMD cert chain: %v", err)
	}

	return err
}

func (p *Plugin) crlVerification(ek []byte, signingKey uint32, config *Config) error {
	var err error
	var caPath string
	if signingKey == 0 {
		caPath = config.VcekAMDCertChain
	} else {
		caPath = config.VlekAMDCertChain
	}

	if config.InsecureCRL {
		p.logger.Warn("InsecureCRL enabled, skipping CRL verification")
	} else {
		err = snp_util.CheckRevocationList(ek, caPath, p.config.VcekCRLUrl, p.config.VlekCRLUrl, signingKey)
		if err != nil {
			if err.Error() == "warn using cache" {
				p.logger.Warn("couldn't fetch CRL using the provided URL. Using cache")
			} else {
				return status.Errorf(codes.Aborted, "failed at CRL verification: %v", err)
			}
		}
	}

	return err
}

func AgentID(pluginName, trustDomain string, report snp.AttestationReport) string {
	chipId := report.ChipId[:10]
	measurement := report.Measurement[:10]
	reportId := report.ReportId[:10]

	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path: path.Join(
			"spire",
			"agent",
			pluginName,
			"chip_id",
			PrintByteArray(chipId[:]),
			"measurement",
			PrintByteArray(measurement[:]),
			"report_id",
			PrintByteArray(reportId[:]),
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

func buildSelectorValues(report snp.AttestationReport, signing_key []byte) []string {
	selectorValues := []string{}

	sha512EK := sha512.Sum512(signing_key)
	measurement := report.Measurement[:]
	policy := snp_util.BuildPolicy(report)
	platforminfo := snp_util.BuildPlatformInfo(report)
	flag := snp_util.BuildFlags(report)

	selectorValues = append(selectorValues, "guest_svn:"+fmt.Sprintf("%d", report.GuestSVN))
	selectorValues = append(selectorValues, "policy:abi_minor:"+fmt.Sprintf("%d", policy.ABI_MINOR))
	selectorValues = append(selectorValues, "policy:abi_major:"+fmt.Sprintf("%d", policy.ABI_MAJOR))
	selectorValues = append(selectorValues, "policy:smt:"+fmt.Sprintf("%t", policy.SMT_ALLOWED))
	selectorValues = append(selectorValues, "policy:migrate_ma:"+fmt.Sprintf("%t", policy.MIGRATE_MA_ALLOWED))
	selectorValues = append(selectorValues, "policy:debug:"+fmt.Sprintf("%t", policy.DEBUG_ALLOWED))
	selectorValues = append(selectorValues, "policy:single_socket:"+fmt.Sprintf("%t", policy.SINGLE_SOCKET_ALLOWED))
	selectorValues = append(selectorValues, "family_id:"+PrintByteArray(report.FamilyId[:]))
	selectorValues = append(selectorValues, "image_id:"+PrintByteArray(report.ImageId[:]))
	selectorValues = append(selectorValues, "vmpl:"+fmt.Sprintf("%d", report.VMPL))
	selectorValues = append(selectorValues, "signature_algo:"+fmt.Sprintf("%d", report.SignatureAlgo))
	selectorValues = append(selectorValues, "current_tcb:boot_loader:"+fmt.Sprintf("%d", report.CurrentTCB.BootLoader))
	selectorValues = append(selectorValues, "current_tcb:tee:"+fmt.Sprintf("%d", report.CurrentTCB.TEE))
	selectorValues = append(selectorValues, "current_tcb:snp:"+fmt.Sprintf("%d", report.CurrentTCB.SNP))
	selectorValues = append(selectorValues, "current_tcb:microcode:"+fmt.Sprintf("%d", report.CurrentTCB.Microcode))
	selectorValues = append(selectorValues, "platform_info:smt_en:"+fmt.Sprintf("%t", platforminfo.SMT_EN))
	selectorValues = append(selectorValues, "platform_info:tsme_en:"+fmt.Sprintf("%t", platforminfo.TSME_EN))
	selectorValues = append(selectorValues, "signing_key:"+fmt.Sprintf("%d", flag.SIGNING_KEY))
	selectorValues = append(selectorValues, "mask_chip_key:"+fmt.Sprintf("%t", flag.MASK_CHIP_KEY))
	selectorValues = append(selectorValues, "author_key_en:"+fmt.Sprintf("%t", flag.AUTHOR_KEY_EN))
	selectorValues = append(selectorValues, "measurement:"+PrintByteArray(measurement[:]))
	selectorValues = append(selectorValues, "host_data:"+PrintByteArray(report.HostData[:]))
	selectorValues = append(selectorValues, "id_key_digest:"+PrintByteArray(report.IdKeyDigest[:]))
	selectorValues = append(selectorValues, "author_key_digest:"+PrintByteArray(report.AuthorKeyDigest[:]))
	selectorValues = append(selectorValues, "report_id_ma:"+PrintByteArray(report.ReportIdMA[:]))
	selectorValues = append(selectorValues, "reported_tcb:boot_loader:"+fmt.Sprintf("%d", report.ReportedTCB.BootLoader))
	selectorValues = append(selectorValues, "reported_tcb:tee:"+fmt.Sprintf("%d", report.ReportedTCB.TEE))
	selectorValues = append(selectorValues, "reported_tcb:snp:"+fmt.Sprintf("%d", report.ReportedTCB.SNP))
	selectorValues = append(selectorValues, "reported_tcb:microcode:"+fmt.Sprintf("%d", report.ReportedTCB.Microcode))
	selectorValues = append(selectorValues, "chip_id:"+PrintByteArray(report.ChipId[:]))
	selectorValues = append(selectorValues, "committed_tcb:boot_loader:"+fmt.Sprintf("%d", report.CommitedTCB.BootLoader))
	selectorValues = append(selectorValues, "committed_tcb:tee:"+fmt.Sprintf("%d", report.CommitedTCB.TEE))
	selectorValues = append(selectorValues, "committed_tcb:snp:"+fmt.Sprintf("%d", report.CommitedTCB.SNP))
	selectorValues = append(selectorValues, "committed_tcb:microcode:"+fmt.Sprintf("%d", report.CommitedTCB.Microcode))
	selectorValues = append(selectorValues, "current_build:"+fmt.Sprintf("%d", report.CurrentBuild))
	selectorValues = append(selectorValues, "current_minor:"+fmt.Sprintf("%d", report.CurrentMinor))
	selectorValues = append(selectorValues, "current_major:"+fmt.Sprintf("%d", report.CurrentMajor))
	selectorValues = append(selectorValues, "committed_build:"+fmt.Sprintf("%d", report.CommitedBuild))
	selectorValues = append(selectorValues, "committed_minor:"+fmt.Sprintf("%d", report.CommitedMinor))
	selectorValues = append(selectorValues, "committed_major:"+fmt.Sprintf("%d", report.CommitedMajor))
	selectorValues = append(selectorValues, "launch_tcb:boot_loader:"+fmt.Sprintf("%d", report.LaunchTCB.BootLoader))
	selectorValues = append(selectorValues, "launch_tcb:tee:"+fmt.Sprintf("%d", report.LaunchTCB.TEE))
	selectorValues = append(selectorValues, "launch_tcb:snp:"+fmt.Sprintf("%d", report.LaunchTCB.SNP))
	selectorValues = append(selectorValues, "launch_tcb:microcode:"+fmt.Sprintf("%d", report.LaunchTCB.Microcode))
	selectorValues = append(selectorValues, "signing_key_hash:"+PrintByteArray(sha512EK[:]))

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
