# AMD SEV SNP SPIRE Plugin

An AMD SEV-SNP Node attestation plugin for SPIRE Server and SPIRE Agent.

## Server plugin: NodeAttestor "amd_sev_snp"

*Must be used in conjunction with the agent-side amd_sev_snp plugin*

The `amd_sev_snp` plugin attests to nodes that have AMD SEV-SNP technology through an out-of-band mechanism.

Plugin steps summary:

1. The plugin receives the request attestation with VCEK from SPIRE Agent and verifies that this VCEK was signed by the AMD root keys.

2. The plugin sends a nonce to SPIRE Agent that will be used to create the attestation report.

3. The plugin receives the attestation report from SPIRE Agent and verifies if the attestation report has the nonce and it was signed by VCEK provided and issues a spiffe id with an uuid that identify uniquely this Agent.

The attestation report has a couple of information about the node:

* **measurement**: Launch Measurement of the Guest AMD SEV-SNP.
* **policy**: The guest policy that the guest owner provides to the firmware during launch.

The SPIFFE ID produced by the server-side `amd_sev_snp` plugin is based on this information that the attestation report has.

The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/amd_sev_snp/<uuid>/measument/<measurement>/policy/<policy>
```

| Configuration           | Description                                                                                                                                                                                       | Default |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `amd_cert_chain`         | ASK/ARK certificates chain provided by AMD. |         |  |

A sample configuration:

```hcl
    NodeAttestor "amd_sev_snp" {
        plugin_data {
            amd_cert_chain = "<path/to/amd_certchain>"
        }
    }
```

### Selectors

| Selector                    | Example                                                           | Description                                                                              |
|-----------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------|
|  SHA1 measurement | `measurement:31b98075bee6ab756702f7a3692c92edb5f2cc0a`                                | Launch measurement of the AMD SEV-SNP machine.                                                               |
| Policy         | `policy:0x30000`                               | The AMD SEV-SNP guest policy sent to firmware during launch.                                                                |
| SHA1 VCEK            | `vcek:27e69b7334fb0e60597ff519f46eb667f7d147d6`  | The VCEK SHA1. |

## Agent plugin: NodeAttestor "amd_sev_snp"

*Must be used in conjunction with the server-side amd_sev_snp plugin*

The `amd_sev_snp` plugin provides attestation data for a node that has the AMD SEV-SNP technology through an out-of-band mechanism.

Plugin steps summary:

1. The plugin gets the VCEK in the vcek_path and sends it in his attestation request to SPIRE Server.

2. The plugin receives a nonce from SPIRE Server and uses it to create an attestation report.

3. The plugin sends this attestation report to SPIRE Server.

The attestation report has a couple of information about the node:

* **measurement**: Launch Measurement of the Guest AMD SEV-SNP.
* **policy**: The guest policy that the guest owner provides to the firmware during launch.

The SPIFFE ID produced by the server-side `amd_sev_snp` plugin is based on this information that the attestation report has.

The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/amd_sev_snp/<uuid>/measument/<measurement>/policy/<policy>
```

| Configuration                    | Description                                                                          | Default                                                   |
|----------------------------------|--------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `vcek_path`                      | Path to a public ECDSA key which is unique to each AMD chip running a specific TCB version.        |  |

A sample configuration:

```hcl
    NodeAttestor "amd_sev_snp" {
        plugin_data {
	        vcek_path = "<path/to/vcek>"
        }
}
```

### Compatibility considerations

+ This plugin is designed to work with AMD SEV-SNP VMs. For more information check [this](https://developer.amd.com/sev/) documentation.

## For testing the plugin

An AMD SEV-SNP VM is required to test this plugin. In `amd-sev-snp` directory run this command bellow.

```
sudo su
export PATH=$PATH:/usr/local/go/bin
# must be executed as root
make test
```

## Demo

To run a demonstration of the plugin, follow [these steps](./docs/demo.md).

