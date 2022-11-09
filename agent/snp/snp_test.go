package snp_test

import (
	"testing"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire-plugin-sdk/templates/agent/nodeattestor"
)

func Test(t *testing.T) {
	plugin := new(nodeattestor.Plugin)
	naClient := new(nodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: nodeattestorv1.NodeAttestorPluginServer(plugin),
		PluginClient: naClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(plugin),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})
}
