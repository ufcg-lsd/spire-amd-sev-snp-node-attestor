package snp

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

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
	trustDomain  spiffeid.TrustDomain
	EKCertChains []string `hcl:"cert_chains"`
	CRLURLs      []string `hcl:"crl_urls"`
	InsecureCRL  bool     `hcl:"insecure_crl"`
	MinFWVersion string   `hcl:"min_fw_version"`
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
	if bytes.Equal(attestationType, []byte("AZURE")) {
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

	err = p.validadeEndorsmentKey(ek, config)
	if err != nil {
		return err
	}

	err = p.crlVerification(ek, config)
	if err != nil {
		return err
	}

	valid := snp_util.ValidateGuestReportAgainstEK(&reportBytes, &ek)
	if !valid {
		return status.Errorf(codes.Internal, "unable to validate guest report against AMD EK")
	}

	report := snp.BuildExpandedAttestationReport(reportBytes)

	var spiffeID string
	var selectors []string

	spiffeID = AgentID(pluginName, config.trustDomain.String(), report)
	selectors = buildSelectorValues(report, ek, config)
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

func (p *Plugin) validadeEndorsmentKey(ek []byte, config *Config) error {
	var valid = false
	var err error

	for _, certChainPath := range config.EKCertChains {
		valid, err = snp_util.ValidateEKCertChain(ek, certChainPath)
		if valid {
			return nil
		}
	}

	return status.Errorf(codes.InvalidArgument, "unable to validate AMD EK with AMD cert chain: %v", err)
}

func (p *Plugin) crlVerification(ek []byte, config *Config) error {
	var err error
	var isRevoked bool = false

	if config.InsecureCRL {
		p.logger.Warn("InsecureCRL enabled, skipping CRL verification")
	} else {
		for _, caPath := range config.EKCertChains {
			for _, crlURL := range config.CRLURLs {
				isRevoked, err = snp_util.IsCertRevoked(ek, caPath, crlURL)
				if isRevoked {
					return errors.New("the EK certificate is revoked")
				} else if err != nil && err.Error() == "warn using cache" {
					p.logger.Warn("couldn't fetch CRL using the provided URL. Using cache")
				}
			}
		}
	}

	return err
}

func AgentID(pluginName, trustDomain string, report snp.AttestationReportExpanded) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path: path.Join(
			"spire",
			"agent",
			pluginName,
			"chip_id",
			hex.EncodeToString(report.ChipId[:10]),
			"measurement",
			hex.EncodeToString(report.Measurement[:10]),
			"report_id",
			hex.EncodeToString(report.ReportId[:10]),
		),
	}

	return u.String()
}

func buildSelectorValues(report snp.AttestationReportExpanded, signing_key []byte, config *Config) []string {
	selectorValues := []string{}

	sha512EK := sha512.Sum512(signing_key)
	measurement := report.Measurement[:]

	if config.MinFWVersion != "" {
		minFWVerion, _ := hex.DecodeString(config.MinFWVersion)
		if report.CurrentTCB.SNP >= minFWVerion[0] {
			selectorValues = append(selectorValues, "fw_version:updated")
		}
	}

	selectorValues = append(selectorValues, "guest_svn:"+fmt.Sprintf("%d", report.GuestSVN))
	selectorValues = append(selectorValues, "policy:abi_minor:"+fmt.Sprintf("%d", report.Policy.ABI_MINOR))
	selectorValues = append(selectorValues, "policy:abi_major:"+fmt.Sprintf("%d", report.Policy.ABI_MAJOR))
	selectorValues = append(selectorValues, "policy:smt:"+fmt.Sprintf("%t", report.Policy.SMT_ALLOWED))
	selectorValues = append(selectorValues, "policy:migrate_ma:"+fmt.Sprintf("%t", report.Policy.MIGRATE_MA_ALLOWED))
	selectorValues = append(selectorValues, "policy:debug:"+fmt.Sprintf("%t", report.Policy.DEBUG_ALLOWED))
	selectorValues = append(selectorValues, "policy:single_socket:"+fmt.Sprintf("%t", report.Policy.SINGLE_SOCKET_ALLOWED))
	selectorValues = append(selectorValues, "family_id:"+hex.EncodeToString(report.FamilyId[:]))
	selectorValues = append(selectorValues, "image_id:"+hex.EncodeToString(report.ImageId[:]))
	selectorValues = append(selectorValues, "vmpl:"+fmt.Sprintf("%d", report.VMPL))
	selectorValues = append(selectorValues, "signature_algo:"+fmt.Sprintf("%d", report.SignatureAlgo))
	selectorValues = append(selectorValues, "current_tcb:boot_loader:"+fmt.Sprintf("%d", report.CurrentTCB.BootLoader))
	selectorValues = append(selectorValues, "current_tcb:tee:"+fmt.Sprintf("%d", report.CurrentTCB.TEE))
	selectorValues = append(selectorValues, "current_tcb:snp:"+fmt.Sprintf("%d", report.CurrentTCB.SNP))
	selectorValues = append(selectorValues, "current_tcb:microcode:"+fmt.Sprintf("%d", report.CurrentTCB.Microcode))
	selectorValues = append(selectorValues, "platform_info:smt_en:"+fmt.Sprintf("%t", report.PlatformInfo.SMT_EN))
	selectorValues = append(selectorValues, "platform_info:tsme_en:"+fmt.Sprintf("%t", report.PlatformInfo.TSME_EN))
	selectorValues = append(selectorValues, "platform_info:ciphertext_hiding_en:"+fmt.Sprintf("%t", report.PlatformInfo.CIPHERTEXT_HIDING_EN))
	selectorValues = append(selectorValues, "platform_info:ecc_en:"+fmt.Sprintf("%t", report.PlatformInfo.ECC_EN))
	selectorValues = append(selectorValues, "platform_info:rapl_dis:"+fmt.Sprintf("%t", report.PlatformInfo.RAPL_DIS))
	selectorValues = append(selectorValues, "signing_key:"+fmt.Sprintf("%d", report.Flags.SIGNING_KEY))
	selectorValues = append(selectorValues, "mask_chip_key:"+fmt.Sprintf("%t", report.Flags.MASK_CHIP_KEY))
	selectorValues = append(selectorValues, "author_key_en:"+fmt.Sprintf("%t", report.Flags.AUTHOR_KEY_EN))
	selectorValues = append(selectorValues, "measurement:"+hex.EncodeToString(measurement[:]))
	selectorValues = append(selectorValues, "host_data:"+hex.EncodeToString(report.HostData[:]))
	selectorValues = append(selectorValues, "id_key_digest:"+hex.EncodeToString(report.IdKeyDigest[:]))
	selectorValues = append(selectorValues, "author_key_digest:"+hex.EncodeToString(report.AuthorKeyDigest[:]))
	selectorValues = append(selectorValues, "report_id_ma:"+hex.EncodeToString(report.ReportIdMA[:]))
	selectorValues = append(selectorValues, "reported_tcb:boot_loader:"+fmt.Sprintf("%d", report.ReportedTCB.BootLoader))
	selectorValues = append(selectorValues, "reported_tcb:tee:"+fmt.Sprintf("%d", report.ReportedTCB.TEE))
	selectorValues = append(selectorValues, "reported_tcb:snp:"+fmt.Sprintf("%d", report.ReportedTCB.SNP))
	selectorValues = append(selectorValues, "reported_tcb:microcode:"+fmt.Sprintf("%d", report.ReportedTCB.Microcode))
	selectorValues = append(selectorValues, "chip_id:"+hex.EncodeToString(report.ChipId[:]))
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
	selectorValues = append(selectorValues, "signing_key_hash:"+hex.EncodeToString(sha512EK[:]))

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

	if config.MinFWVersion != "" {
		splittedValue := strings.Split(config.MinFWVersion, "x")
		_, err := hex.DecodeString(splittedValue[1])

		if err != nil {
			return nil, err
		}

		config.MinFWVersion = splittedValue[1]
	}

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
