package snp

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	snp "snp/common"
	"sync"
	"unsafe"

	snputil "snp/agent/snp/snputil"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
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

func IntToByteArray(num int16) []byte {
	size := int(unsafe.Sizeof(num))
	arr := make([]byte, size)
	for i := 0; i < size; i++ {
		byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&num)) + uintptr(i)))
		arr[i] = byt
	}
	return arr
}

func (p *Plugin) AttestationAzureSNP(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte("Attestation Azure"),
		},
	})
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send attestation data: %v", st.Message())
	}

	challenge, err := stream.Recv()
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to receive challenges: %v", st.Message())
	}

	nonce := sha256.Sum256(challenge.Challenge)

	report, err := snputil.GetReportTPM()

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get report: %v", err)
	}

	config, _ := p.getConfig()
	var key []byte

	if config.Ek == "" {
		key, err = snputil.GetVCEK()
	}else {
		key, err = os.ReadFile(config.Ek)
	}
	if err != nil {
		return status.Errorf(codes.Internal, "Error: %v", err)
	}

	ak, nil := snputil.GetAK()
	if err != nil {
		return status.Errorf(codes.Internal, "Error trying to get AK: %v", err)
	}

	runtimeData, err := snputil.GetRuntimeData()

	attestationData, err := json.Marshal(snp.AttestationRequestAzure{
		Report:      report,
		Cert:        key,
		TPMCert:     ak,
		RuntimeData: runtimeData,
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
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send challenge response: %s", st.Message())
	}

	quote, sig, err := snputil.GetQuoteTPM(nonce)

	quoteData, err := json.Marshal(snp.QuoteData{
		Quote: quote,
		Sig:   sig,
	})

	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal quote data: %v", err)
	}
	recv, err := stream.Recv()
	if err != nil {
		log.Fatal(err)
		fmt.Print(recv)
	}
	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: quoteData,
		},
	})

	return nil
}

func (p *Plugin) AttestationSNP(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(" "),
		},
	})

	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send attestation data: %v", st.Message())
	}

	challenge, err := stream.Recv()

	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to receive challenges: %v", st.Message())
	}

	nonce := sha512.Sum512(challenge.Challenge)

	device, err := client.OpenDevice()
	defer device.Close()

	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to open device: %v", st.Message())
	}

	config, _ := p.getConfig()
	var certificateTable []byte
	var report []byte

	if config.Ek == "" {
		report, certificateTable, err = client.GetRawExtendedReport(device, nonce)
	} else {
		report, err = client.GetRawReport(device, nonce)
	}

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get report: %v", err)
	}

	key, err := p.getChipKey(certificateTable, report)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to get ek: %v", err)
	}

	attestationData, err := json.Marshal(snp.AttestationRequest{
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
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send challenge response: %s", st.Message())
	}

	return nil
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	device := "/dev/sev-guest"
	if _, err := os.Stat(device); os.IsNotExist(err) {
		return p.AttestationAzureSNP(stream)
	}
	return p.AttestationSNP(stream)
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

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
func (p *Plugin) getChipKey(certificateTable []byte, report []byte) ([]byte, error) {

	var err error
	var ek []byte
	signingKey := snp.GetSigningKey(&report)
	config, _ := p.getConfig()

	if config.Ek != "" {
		ek, err = os.ReadFile(config.Ek)
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
