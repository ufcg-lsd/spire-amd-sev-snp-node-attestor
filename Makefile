BUILD_PATH = "./bin"

AGENT_PLUGIN_PATH = ${BUILD_PATH}/"snp-agent-plugin"
SERVER_PLUGIN_PATH = ${BUILD_PATH}/"snp-server-plugin"

build-agent:
	mkdir -p ${BUILD_PATH}

	go build -o ${AGENT_PLUGIN_PATH} agent/agent_plugin.go

build-server:
	mkdir -p ${BUILD_PATH}

	go build -o ${SERVER_PLUGIN_PATH} server/server_plugin.go

build:
	mkdir -p ${BUILD_PATH}

	go build -o ${SERVER_PLUGIN_PATH} server/server_plugin.go
	go build -o ${AGENT_PLUGIN_PATH} agent/agent_plugin.go

test:
	go test ./tests

test-coverage:
	go test ./tests -v -cover -coverpkg=./... -coverprofile testing_profile
	go tool cover -func=./testing_profile
