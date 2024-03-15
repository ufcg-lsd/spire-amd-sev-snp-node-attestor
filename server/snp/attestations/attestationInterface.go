package attestations

import nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"

type AttestationServer interface{
	GetAttestationData(stream nodeattestorv1.NodeAttestor_AttestServer) ([]byte, []byte, error)
}