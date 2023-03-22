BUILD_PATH = "./"

AGENT_PLUGIN_PATH = ${BUILD_PATH}/"snp-agent-plugin"
SERVER_PLUGIN_PATH = ${BUILD_PATH}/"snp-server-plugin"

build-agent:
	go build -o ${AGENT_PLUGIN_PATH} agent/agent_plugin.go

build-server:
	go build -o ${SERVER_PLUGIN_PATH} server/server_plugin.go

build:
	go build -o ${SERVER_PLUGIN_PATH} server/server_plugin.go
	go build -o ${AGENT_PLUGIN_PATH} agent/agent_plugin.go

test:
	go test ./agent/snp/
