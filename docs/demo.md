# Demo 01

## 1. Dependencies.

* A Virtual Machine with Ubuntu 20.04 and SEV-SNP enabled (follow [this doc](https://git.lsd.ufcg.edu.br/securedsp/AMDSEV/-/tree/snp-v1) to learn how to configure a SEV-SNP Host and Guest);
* A valid [GoLang installation](https://go.dev/doc/install) in the VM;

## 2. Configuring the SPIRE Server.

```NOTE: Notice that you can run the SPIRE Server on any machine, as the Agent is the one that will be attested it must be in a SNP confidential VM, but that is no need for the Server to be running in a confidential VM. In this demo, we will build the Server in an arbitrary VM for simplicity purposes but you can build the Server on any machine you prefer as long as you can trust it.```

### 2.1. Building the SPIRE Server

First of all, let's update and upgrade the packages of your OS to guarantee that everything is up-to-date.

```sh
sudo apt update -y
sudo apt install build-essential -y
sudo apt upgrade -y
```

Now, let's clone the SPIRE Project repo and build it:

Building the Server:

```sh
# Clone the repository and go to the folder
git clone https://github.com/spiffe/spire
cd spire/

# Build the server cli application
go build ./cmd/spire-server

# Copy the binaries to /usr/bin so you can have
# access to 'spire-server' commands
sudo cp -r ./spire-server /usr/bin/

# To test the installation, run:
spire-server --version
```

now, you can copy the `conf` file inside SPIRE repository to `/home/$USER`.

```
cp -r conf/ ~/
cd ~/
```

### 2.2. Building the plugin.

Now let's clone the plugin repository.

```sh
git clone https://git.lsd.ufcg.edu.br/securedsp/amd-sev-snp-plugin.git
cd amd-sev-snp-plugin/
```

build the server plugin.

```sh
make build-server BUILD_PATH=<PATH_TO_BUILD>

# It will generate a <PATH_TO_BUILD>/snp-server binary, which is the server plugin binary
# To simplify, you can set "~/" as the build path.
```

Now, you can replace the file you have copied to `/home/$USER/conf/server/server.conf` with the `server.conf` file of this repository.

```sh
mv server.conf ~/conf/server/server.conf
cd ~/
```

### 2.3. Spire Server configuration file.

The **plugin_cmd** configs in the NodeAttestor **sev-snp** are not set in `~/conf/server/server.conf`, you must replace the **plugin_cmd** with the path of the server sev-snp plugin binary that you have built. 

```conf
# server.conf
NodeAttestor "sev_snp" {
    plugin_cmd = "<path_to_plugin_binary>"
    plugin_checksum = ""
    plugin_data {
        amd_cert_chain = "<path/to/amd_certchain>"
    }
}
```

You can find how to download the cert chain for your AMD secure processor following [this docs](https://www.amd.com/system/files/TechDocs/57230.pdf), in the section 4.2 (Get Certificate Chain). The base URL for the download is: https://kdsintf.amd.com/.

## 3. Configuring the SPIRE Agent.

### 3.1. Building the SPIRE Agent

Now, from inside the SEV-SNP Guest VM, let's configure the SPIRE Agent.
First of all, let's update and upgrade the packages of your OS to guarantee that everything is up-to-date.

```sh
sudo apt update -y
sudo apt install build-essential -y
sudo apt upgrade -y
```

Now, let's clone the SPIRE Project repo and build it:

Building the Agent:

```sh
# Clone the repository and go to the folder
git clone https://github.com/spiffe/spire
cd spire/

# Build the agent cli application
go build ./cmd/spire-agent

# Copy the binaries to /usr/bin so you can have
# access to 'spire-agent' commands
sudo cp -r ./spire-agent /usr/bin/

# To test the installation, run:
spire-agent --version
```

now, you can copy the `conf` file inside SPIRE repository to `/home/$USER`.

```
cp -r conf/ ~/
cd ~/
```

### 3.2. Building the plugin.

Now let's clone the plugin repository.

```sh
git clone https://git.lsd.ufcg.edu.br/securedsp/amd-sev-snp-plugin.git
cd amd-sev-snp-plugin/
```

build the agent plugin.

```sh
make build-agent BUILD_PATH=<PATH_TO_BUILD>

# It will generate a <PATH_TO_BUILD>/snp-agent binary, which is the agent plugin binary
# To simplify, you can set "~/" as the build path.
```

Now, you can replace the file you have copied to `/home/$USER/conf/agent/agent.conf` with the `agent.conf` file of this repository.

```sh
mv agent.conf ~/conf/agent/agent.conf
cd ~/
```

### 3.3 Spire Agent configuration file.

```conf
# agent.conf
agent {
    ...
    server_address = "<server_address>"
    server_port = "<server_port>"
    ...
}

plugins {
    NodeAttestor "sev_snp" {
        plugin_cmd = "<path/to/plugin/binary>"
        plugin_checksum = ""
        plugin_data {
	        vcek_path = "<path/to/vcek.pem>"
        }

    }
    ...
}
```

The **plugin_cmd** and **vcek_path** configs in the NodeAttestor **sev-snp** are not set in `~/conf/agent/agent.conf`, you must replace the **plugin_cmd** with the path of the agent sev-snp plugin binary that you have built and the **vcek_path** with the path to the SEV-SNP Versioned Chip Endorsement Key (VCEK). To obtain the VCEK, you can follow [these steps](./get-vcek-from-guest.md). You must configure the `server_address` and `server_port` with your SPIRE Server address and port.

After configuring the Agent and Server, verify if they are communicating (you can run the steps in section 4) and then you can shutdown the VM and follow [these steps](https://git.lsd.ufcg.edu.br/securedsp/AMDSEV/-/blob/snp-v1/docs/dm-verity-setup.md) if you want to configure the filesystem verification on the Guest VM. It is important because the filesystem verification is made using the initramfs, and as the initramfs is included in the attestation report that is used to attest the VM, you can establish a chain of trust, with the initramfs verifying the integrity of the VM's filesystem, and the measurement verifying the integrity of the initramfs. After configuring the filesystem verification, come back here and run the steps of section 4 again.

## 4. Running the demo

Now, with everything setted up, it's time to run!

First, from the machine that will be running the SPIRE Server, run the following command:

```bash
sudo spire-server run --config <path_to_server.conf>
```

Now, from the VM, let's run the SPIRE Agent

```bash
sudo spire-agent run --config <path_to_agent.conf>
```

If everything is well configured, you must see something like this in the Agents logs:

```bash
INFO[0000] Node attestation was successful               rettestable=false spiffe_id="spiffe://lsd.ufcg.edu.br/spire/agent/sev_snp/24f364f5-b4f6-44a9-b0a3-15044f2e87ca/measurement/956423b32d2afa1f659ba458ae9b3147d2b734db/policy/0x30000" subsystem_name=attestor trust_domain_id="spiffe://lsd.ufcg.edu.br"
```
