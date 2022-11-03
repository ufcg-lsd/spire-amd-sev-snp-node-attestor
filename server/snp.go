package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path"
	"sync"
	"unsafe"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// This compile time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	// TODO: Remove if the plugin does not need the logger.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)

	// This compile time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsHostServices interface.
	// TODO: Remove if the plugin does not need host services.
	_ pluginsdk.NeedsHostServices = (*Plugin)(nil)
)

const (
	pluginName = "sev_snp"
)

// Config defines the configuration for the plugin.
// TODO: Add relevant configurables or remove if no configuration is required.
type Config struct {
	trustDomain    spiffeid.TrustDomain
	AMDCertChain   string `hcl:"amd_cert_chain"`
	SevtoolBinPath string `hcl:"sevtool_bin_path"`
}

// Plugin implements the NodeAttestor plugin
type Plugin struct {
	// UnimplementedNodeAttestorServer is embedded to satisfy gRPC
	nodeattestorv1.UnimplementedNodeAttestorServer

	// UnimplementedConfigServer is embedded to satisfy gRPC
	// TODO: Remove if this plugin does not require configuration
	configv1.UnimplementedConfigServer

	// Configuration should be set atomically
	// TODO: Remove if this plugin does not require configuration
	configMtx sync.RWMutex
	config    *Config

	// The logger received from the framework via the SetLogger method
	// TODO: Remove if this plugin does not need the logger.
	logger hclog.Logger
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
// TODO: Remove if the plugin does not need the logger.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// BrokerHostServices is called by the framework when the plugin is loaded to
// give the plugin a chance to obtain clients to SPIRE host services.
// TODO: Remove if the plugin does not need host services.
func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	// TODO: Use the broker to obtain host service clients
	return nil
}

func ByteArrayToInt(arr []byte) int16 {
	val := int16(0)
	size := len(arr)
	for i := 0; i < size; i++ {
		*(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&val)) + uintptr(i))) = arr[i]
	}
	return val
}

func generateNonce(length uint8) []byte {
	nonce := make([]byte, length)
	rand.Read(nonce)

	return nonce
}

func validateVCEKCertChain(vcek []byte, rootPath string) (bool, error) {
	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return false, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return false, err
	}

	block, _ := pem.Decode([]byte(vcek))
	if block == nil {
		return false, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return false, err
	}

	return true, nil
}

// Attest implements the NodeAttestor Attest RPC
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

	valid, err := validateVCEKCertChain(vcek, config.AMDCertChain)

	if !valid {
		return err
	}

	nonce := generateNonce(uint8(16))
	sha512Nonce := sha512.Sum512(nonce)

	stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: nonce,
		},
	})

	challengeRes, _ := stream.Recv()

	report := challengeRes.GetChallengeResponse()

	file, _ := os.Create("guest_report.bin")
	defer file.Close()
	file.Write(report)

	err = ValidateGuestReport(file, config.SevtoolBinPath)

	if err != nil {
		return err
	}

	file, _ = os.Open("guest_report.bin")
	parsedReport := LoadAttestationReport(file)

	p.logger.Debug(PrintByteArray(parsedReport.ReportData[:]))

	if parsedReport.ReportData != sha512Nonce {
		return errors.New("invalid nonce received in report")
	}

	var spiffeID string
	var selectors []string

	spiffeID = AgentID(pluginName, config.trustDomain.String(), parsedReport)
	selectors = buildSelectorValues(parsedReport, vcek)

	os.Remove("guest_report.bin")

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

func AgentID(pluginName, trustDomain string, report AttestationReport) string {
	sha1Measurement := sha1.Sum(report.Measurement[:])

	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path: path.Join(
			"spire",
			"agent",
			pluginName,
			uuid.New().String(),
			"measurement",
			PrintByteArray(sha1Measurement[:]),
			"policy",
			fmt.Sprintf("0x%x", report.Policy),
		),
	}

	return u.String()
}

func buildSelectorValues(report AttestationReport, vcek []byte) []string {
	selectorValues := []string{}

	sha1VCEK := sha1.Sum(vcek)

	selectorValues = append(selectorValues, "measurement:"+PrintByteArray(report.Measurement[:]))
	selectorValues = append(selectorValues, "policy:"+fmt.Sprintf("0x%x", report.Policy))
	selectorValues = append(selectorValues, "vcek:"+PrintByteArray(sha1VCEK[:]))

	return selectorValues
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, tt may be invoked to reconfigure the plugin.
// As such, it should replace the previous configuration atomically.
// TODO: Remove if no configuration is required
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

// setConfig replaces the configuration atomically under a write lock.
// TODO: Remove if no configuration is required
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

// getConfig gets the configuration under a read lock.
// TODO: Remove if no configuration is required
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func main() {
	plugin := new(Plugin)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(plugin),
		// TODO: Remove if no configuration is required
		configv1.ConfigServiceServer(plugin),
	)
}
