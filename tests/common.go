package snp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	agent "snp/agent/snp"
	server "snp/server/snp"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
)

var (
	dir, _       = os.Getwd()
	neverExpires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

type testCases struct {
	serverConf string
	agentConf  string
	name       string
	err        string
}

func loadAgentPlugin(t *testing.T, hclConfig string) agentnodeattestorv1.NodeAttestorClient {

	pluginAgent := new(agent.Plugin)

	nodeAttestorClient := new(agentnodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: agentnodeattestorv1.NodeAttestorPluginServer(pluginAgent),
		PluginClient: nodeAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(pluginAgent),
		},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "domain.test",
		},
	})
	require.NoError(t, err)
	return nodeAttestorClient
}

func loadServerPlugin(t *testing.T, hclConfig string) servernodeattestorv1.NodeAttestorClient {
	pluginServer := new(server.Plugin)
	nodeAttestorClient := new(servernodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: servernodeattestorv1.NodeAttestorPluginServer(pluginServer),
		PluginClient: nodeAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(pluginServer),
		},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "domain.test",
		},
	})
	require.NoError(t, err)
	return nodeAttestorClient
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func generateARK() (*x509.Certificate, *rsa.PrivateKey) {
	caPrivateKey, err := generatePrivateKey()
	if err != nil {
		fmt.Printf("Failed to generate CA private key: %v", err)
		return nil, nil
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(65536),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "ARK-Milan",
		},
		Issuer: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "ARK-Milan",
		},
		NotBefore:             time.Now(),
		NotAfter:              neverExpires,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertificate, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPrivateKey.Public(), caPrivateKey)
	if err != nil {
		fmt.Printf("Failed to generate CA certificate: %v", err)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(caCertificate)
	if err != nil {
		fmt.Printf("Failed to generate CA certificate: %v", err)
		return nil, nil
	}

	return cert, caPrivateKey
}

func generateASK(caTemplate *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	askPrivateKey, err := generatePrivateKey()
	if err != nil {
		fmt.Printf("Failed to generate ask CA private key: %v", err)
		return nil, nil
	}

	askTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(65793),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "SEV-Milan",
		},
		Issuer: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "ARK-Milan",
		},
		NotBefore:             time.Now(),
		NotAfter:              neverExpires,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	askCertificate, err := x509.CreateCertificate(rand.Reader, askTemplate, caTemplate, askPrivateKey.Public(), caPrivateKey)
	if err != nil {
		fmt.Printf("Failed to generate ask CA certificate: %v", err)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(askCertificate)
	if err != nil {
		fmt.Printf("Failed to generate ask CA certificate: %v", err)
		return nil, nil
	}

	return cert, askPrivateKey
}

func generateChipKey(askCert *x509.Certificate, askPrivateKey *rsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA key pair: %v", err)
		return nil, nil
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "SEV-Milan",
		},
		NotBefore:             time.Now(),
		NotAfter:              neverExpires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, askCert, key.Public(), askPrivateKey)
	if err != nil {
		fmt.Printf("Failed to generate certificate: %v", err)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Printf("Failed to generate certificate: %v", err)
		return nil, nil
	}

	return cert, key
}

func generateCRL(askCert *x509.Certificate, askKey *rsa.PrivateKey) *x509.RevocationList {
	crlTemplate := x509.RevocationList{
		Number:             big.NewInt(4),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Issuer:             askCert.Issuer,
		RawIssuer:          askCert.RawIssuer,
		AuthorityKeyId:     askCert.AuthorityKeyId,
		NextUpdate:         time.Now().Add(1000 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, askCert, askKey)
	if err != nil {
		return nil
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil
	}

	return crl
}

func buildCertChain(arkCert, askCert *x509.Certificate) *x509.CertPool {
	certChain := x509.NewCertPool()
	certChain.AddCert(arkCert)
	certChain.AddCert(askCert)

	return certChain
}

func validateEKSignature(cert *x509.Certificate, certChain *x509.CertPool) bool {
	opts := x509.VerifyOptions{
		Roots: certChain,
	}

	_, err := cert.Verify(opts)

	return err == nil
}

func validateCRLSignature(crl *x509.RevocationList, parent *x509.Certificate) bool {
	return crl.CheckSignatureFrom(parent) == nil
}

func store(path, keyType string, bytes []byte, t *testing.T) {
	pemBlock := &pem.Block{
		Type:  keyType,
		Bytes: bytes,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	require.NoError(t, os.WriteFile(path, pemData, 0644))
}

func generateKeys(arkCert *x509.Certificate, arkKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, *x509.RevocationList, *x509.Certificate, *ecdsa.PrivateKey) {
	askCert, askKey := generateASK(arkCert, arkKey)
	askCRL := generateCRL(askCert, askKey)

	cert_chain := buildCertChain(arkCert, askCert)

	ekCert, ekKey := generateChipKey(askCert, askKey)

	valid := validateCRLSignature(askCRL, askCert)
	if !valid {
		panic("Error generating CRL")
	}
	valid = validateEKSignature(ekCert, cert_chain)
	if !valid {
		panic("Error generating EK")
	}

	return askCert, askKey, askCRL, ekCert, ekKey
}

func clean(t *testing.T) {
	require.NoError(t, os.RemoveAll(dir+"/keys/public"))
	require.NoError(t, os.RemoveAll(dir+"/keys/private"))
}

func setupCerts(t *testing.T) {
	require.NoError(t, os.Mkdir(dir+"/keys/public", 0777))
	require.NoError(t, os.Mkdir(dir+"/keys/public/vcek", 0777))
	require.NoError(t, os.Mkdir(dir+"/keys/public/vlek", 0777))
	require.NoError(t, os.Mkdir(dir+"/keys/private", 0777))
	require.NoError(t, os.Mkdir(dir+"/keys/private/vcek", 0777))
	require.NoError(t, os.Mkdir(dir+"/keys/private/vlek", 0777))

	arkCert, arkKey := generateARK()

	askCert, _, askCRL, ekCert, ekKey := generateKeys(arkCert, arkKey)

	require.NoError(t, os.WriteFile(dir+"/keys/public/vcek/crl", askCRL.Raw, 0644))

	certChain := []*x509.Certificate{arkCert, askCert}

	chainPEM := []byte{}
	for _, cert := range certChain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	require.NoError(t, os.WriteFile(dir+"/keys/public/vcek/cert_chain", chainPEM, 0644))

	store(dir+"/keys/public/vcek/cert", "CERTIFICATE", ekCert.Raw, t)
	store("/etc/sev-guest/vcek/public.pem", "CERTIFICATE", ekCert.Raw, t)
	ekKeyBytes, err := x509.MarshalECPrivateKey(ekKey)
	require.NoError(t, err)
	store(dir+"/keys/private/vcek/key.pem", "EC PRIVATE KEY", ekKeyBytes, t)
	store("/etc/sev-guest/vcek/private.pem", "EC PRIVATE KEY", ekKeyBytes, t)

	askCert, _, askCRL, ekCert, ekKey = generateKeys(arkCert, arkKey)

	require.NoError(t, os.WriteFile(dir+"/keys/public/vlek/crl", askCRL.Raw, 0644))

	certChain = []*x509.Certificate{arkCert, askCert}

	chainPEM = []byte{}
	for _, cert := range certChain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	require.NoError(t, os.WriteFile(dir+"/keys/public/vlek/cert_chain", chainPEM, 0644))

	store(dir+"/keys/public/vlek/cert", "CERTIFICATE", ekCert.Raw, t)
	store("/etc/sev-guest/vlek/public.pem", "CERTIFICATE", ekCert.Raw, t)
	ekKeyBytes, err = x509.MarshalECPrivateKey(ekKey)
	require.NoError(t, err)
	store(dir+"/keys/private/vlek/key.pem", "EC PRIVATE KEY", ekKeyBytes, t)
	store("/etc/sev-guest/vlek/private.pem", "EC PRIVATE KEY", ekKeyBytes, t)
}
