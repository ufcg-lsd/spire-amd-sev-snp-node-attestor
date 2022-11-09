BUILD_PATH = "./"

AGENT_PLUGIN_PATH = ${BUILD_PATH}/"snp-agent"
SERVER_PLUGIN_PATH = ${BUILD_PATH}/"snp-server"

export BUILD_PATH

build:
	go build -o ${SERVER_PLUGIN_PATH} server/server_plugin.go
	go build -o ${AGENT_PLUGIN_PATH} agent/agent_plugin.go
