# Dummy SPIRE Plugin

A dummy plugin for SPIRE Node Attestation for SPIRE Server and SPIRE Agent.

## 1. How it works.

The Server Plugin is configured to expect a int16 number that must be `odd`, `even` or `any` (odd or even).

The Agent Plugin is configured to send a random int16 number configured to be `even` or `odd`.

If the Agent Plugin provides a number that matches the expected type from Server Plugin, it receives a SPIFFEID following the template:

`spiffe://{{trust_domain}}/spire/agent/{{plugin_name}}/{{number_type}}/{{number_provided}}}`

## 2. Dependencies.

* A machine with Ubuntu operating system;
* A valid [GoLang](https://go.dev/doc/install) installation;
* A valid [Docker](https://docs.docker.com/engine/install/ubuntu/) installation;

## 3. Running the plugin.

The following steps describe how to configure the plugin to run in an environment running Ubuntu OS, and the SPIRE Agent and SPIRE Server running on the same machine. Notice that you may have to do some changes to run in other environments depending on the configs of it.

### 3.1 Setting up environment.

First of all, let's update and upgrade the packages of your OS to guarantee that everything is up-to-date.

```sh
sudo apt update -y
sudo apt install build-essential -y
sudo apt upgrade -y
```

Now, let's clone the SPIRE Project repo and build it:

```sh
# Clone the repository and go to the folder
git clone https://github.com/spiffe/spire
cd spire/

# Build the server and agent cli applications
go build ./cmd/spire-server
go build ./cmd/spire-agent

# Copy the binaries to /usr/bin so you can have
# access to 'spire-server' and 'spire-agent' commands
sudo cp -r ./spire-server /usr/bin/
sudo cp -r ./spire-agent /usr/bin/
```

To test the installation, run:

```sh
spire-server --version
# 1.4.3-dev-unk
spire-agent --version
# 1.4.3-dev-unk
```

now, you can copy the `conf` file inside SPIRE repository to `/home/$USER`.

```
cp -r conf/ ~/
cd ~/
```

### 3.2 Building the plugin.

Now let's clone the plugin repository.

```sh
git clone https://git.lsd.ufcg.edu.br/securedsp/dummy-spire-plugin.git
cd dummy-spire-plugin/
```

build the agent and the server plugin.

```sh
# Build the agent plugin
cd agent/
go build -o ~/
cd ..

# Build the server plugin
cd server/
go build -o ~/
cd ..
```

## 4. How to configure the Agent and Server files.

First, replace the files you have copied to `/home/$USER/conf/agent/agent.conf` and `/home/$USER/conf/server/server.conf` with the `agent.conf` and `server.conf` files of this repository.

```sh
mv agent.conf ~/conf/agent/agent.conf
mv server.conf ~/conf/server/server.conf
cd ~/
```

### 4.1 Spire Agent configuration file.

The **plugin_cmd** configs in the NodeAttestor **dummy_plugin** are not set in `~/conf/agent/agent.conf`, you must replace the **plugin_cmd** with the path of the agent dummy plugin binary that you have builded. 

```json
# agent.conf
 NodeAttestor "dummy_plugin" {
        plugin_cmd = "path/to/dummy-plugin-agent"
        plugin_checksum = ""
        plugin_data {
            number_type = "odd"
        }
}
```

*if you followed the instructions, the path is `/home/$USER/dummy-plugin-agent`. (notice that you have to replace $USER with your username, env variables are not allowed in the config file)*

Possible values to 
`number_type` config in Agent plugin.

| number_type | Description                                   |
| ----------- | --------------------------------------------- |
| odd         | makes the agent generate a random odd number  |
| even        | makes the agent generate a random even number |


### 4.2 Spire Server configuration file.

The **plugin_cmd** configs in the NodeAttestor **dummy_plugin** are not set in `~/conf/server/server.conf`, you must replace the **plugin_cmd** with the path of the server dummy plugin binary that you have builded. 

```json
# server.conf
NodeAttestor "dummy_plugin" {
	    plugin_cmd = "path/to/dummy-plugin-server"
	    plugin_checksum = ""
	    plugin_data {
	        valid_number_type = "odd"
	    }
}
```

*if you followed the instructions, the path is `/home/$USER/dummy-plugin-server`. (notice that you have to replace $USER with your username, env variables are not allowed in the config file)*

Possible values to `valid_number_type` config in Server plugin.

| valid_number_type | Description                                   |
| ----------------- | --------------------------------------------- |
| odd               | makes server attest just odd numbers          |
| even              | makes server attest just even numbers         |
| any               | makes server attest any number provided to it |

## 5. Running SPIRE with the plugin.

Now that you have configured everything, you can run the SPIRE Server and the SPIRE Agent.

```sh
cd ~/

spire-server run -config conf/server/server.conf

spire-agent run -config conf/agent/agent.conf
```

Depends on your configuration, you must expect that the Agent has been successfully attested or not.

## 6. References

* [Spire SDK for plugin creation](https://github.com/spiffe/spire-plugin-sdk)
* [Spire quickstart for Linux](https://spiffe.io/docs/latest/try/getting-started-linux-macos-x/)
