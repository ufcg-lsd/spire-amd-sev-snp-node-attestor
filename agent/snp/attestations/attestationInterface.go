package attestations

import nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"

type AttestationAgent interface{
	GetAttestationData(stream nodeattestorv1.NodeAttestor_AidAttestationServer, ekPath string) error
}