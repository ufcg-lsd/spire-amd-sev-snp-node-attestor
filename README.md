# AMD SEV-SNP SPIRE Plugin

An AMD SEV-SNP Node attestation plugin for SPIRE Server and SPIRE Agent.

## Attestation Workflow

The `amd_sev_snp` plugin attests to nodes that have AMD SEV-SNP technology through an out-of-band mechanism.

Plugin steps summary:

1. The Server receives the request attestation along with the AMD-SP endorsement key (VCEK or VLEK) from the Agent. 

2. The Server verifies if the AMD root keys signed the endorsement key, and in a positive case, it sends a nonce to the Agent. This nonce will be used to create the attestation report.

3. The Agent requests the attestation report to the AMD-SP.

4. The Server receives the attestation report and verifies if the attestation report has the proper nonce and if it was signed by the AMD-SP endorsement key (VCEK or VLEK) provided. If both verifications succeed, the Server issues an SVID with the REPORT_ID and measurement of that Node that identify uniquely this Agent.

>The attestation report has a couple of information about the node. For more information about the attestation report see [this document](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) in section 7.3 in **Table 21. ATTESTATION_REPORT Structure**.

## Server plugin: NodeAttestor "amd_sev_snp"

The **SPIFFE ID** has the form:

```xml
spiffe://<trust-domain>/spire/agent/amd_sev_snp/chip_id/<truncated_chip_id>/measurement/<truncated_measurement>/report_id/<report_id>
```

### Server Configuration

```hcl
NodeAttestor "amd_sev_snp" {
    plugin_cmd = "<path/to/plugin_binary>"
    plugin_data {
        amd_cert_chain = "<path/to/amd_certchain>"
    }
}
```

The `amd_cert_chain` field refer to the ASK/ARK certificates chain provided by AMD.
To get the one of amd_cert_chain you can use the commands bellow:

```bash
# VLEK
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o cert_chain.pem
# VCEK
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o cert_chain.pem
```

### Agent Configuration

```hcl
NodeAttestor "amd_sev_snp" {
    plugin_cmd = "<path/to/plugin_binary>"
    plugin_data {
    }
}
```


### Selectors

|Selector                                                           | Description                                                                              |
|-------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| `amd_sev_snp:guest_svn:<int>`                                | The guest SVN.                                                               |
| `amd_sev_snp:policy:abi_minor:<int>`                                | The guest policy. The minimum ABI minor version required for this guest to run.                                                               |
| `amd_sev_snp:policy:abi_major:<int>`                                | The guest policy. The minimum ABI major version required for this guest to run.                                                               |
| `amd_sev_snp:policy:smt:<bool>`                                | The guest policy. <br/> false: SMT is disallowed.<br/> true: SMT is allowed.                                                              |
| `amd_sev_snp:policy:migrate_ma:<bool>`                                | The guest policy. <br/> false: Association with a migration agent is disallowed. <br/> true: Association with a migration agent is allowed. |
| `amd_sev_snp:policy:debug:<bool>`                                | The guest policy. <br/> false: Debugging is disallowed. <br/> true: Debugging is allowed. |
| `amd_sev_snp:policy:single_socket:<bool>`                                | The guest policy. <br/> false: Guest can be activated on multiple sockets. <br/> false: Guest can be activated only on one socket. |
| `amd_sev_snp:family_id:<string>`                                | The family ID provided at launch. |
| `amd_sev_snp:image_id:<string>`                                | The image ID provided at launch. |
| `amd_sev_snp:vmpl:<int>`                                | The request VMPL for the attestation report. |
| `amd_sev_snp:signature_algo:<int>`                                | The signature algorithm used to sign this report. |
| `amd_sev_snp:current_tcb:boot_loader:<int>`                                | Current bootloader version. SVN of PSP bootloader. |
| `amd_sev_snp:current_tcb:tee:<int>`                                | Current PSP OS version. SVN of PSP operating system. |
| `amd_sev_snp:current_tcb:snp:<int>`                                | Version of the SNP firmware. Security Version Number (SVN) of SNP firmware. |
| `amd_sev_snp:current_tcb:microcode:<int>`                             | Lowest current patch level of all cores. |
| `amd_sev_snp:platform_info:smt_en:<bool>`                             | Indicates that SMT is enabled in the system. |
| `amd_sev_snp:platform_info:tsme_en:<bool>`                             | Indicates that TSME is enabled in the system. |
| `amd_sev_snp:signing_key:<int>`                             | Encodes the key used to sign this report. <br/> 0: VCEK. <br/> 1: VLEK. <br/> 2–6: Reserved. <br/> 7: None <br/> |
| `amd_sev_snp:mask_chip_key:<string>`                             | The value of MaskChipKey. |
| `amd_sev_snp:author_key_digest:<string>`                             | Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn. |
| `amd_sev_snp:measurement:<string>`                                | Launch measurement of the AMD SEV-SNP machine. |
| `amd_sev_snp:host_data:<string>`                                | Data provided by the hypervisor at launch. |
| `amd_sev_snp:id_key_digest:<string>` | SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH. |
| `amd_sev_snp:author_key_digest:<string>` | SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH. Zeroes if AUTHOR_KEY_EN is 1. |
| `amd_sev_snp:report_id_ma:<string>` | Report ID of this guest’s migration agent. |
| `amd_sev_snp:reported_tcb:boot_loader:<int>`                                | Current bootloader version. SVN of PSP bootloader. |
| `amd_sev_snp:reported_tcb:tee:<int>`                                | Current PSP OS version. SVN of PSP operating system. |
| `amd_sev_snp:reported_tcb:snp:<int>`                                | Version of the SNP firmware. Security Version Number (SVN) of SNP firmware. |
| `amd_sev_snp:reported_tcb:microcode:<int>`                             | Lowest current patch level of all cores. |
| `amd_sev_snp:chip_id:<string>`                             | If MaskChipId is set to 0, Identifier unique to the chip as output by GET_ID. Otherwise, set to 0h. |
| `amd_sev_snp:committed_tcb:boot_loader:<int>`                                | Current bootloader version. SVN of PSP bootloader. |
| `amd_sev_snp:committed_tcb:tee:<int>`                                | Current PSP OS version. SVN of PSP operating system. |
| `committed_tcb:snp:<int>`                                | Version of the SNP firmware. Security Version Number (SVN) of SNP firmware. |
| `amd_sev_snp:committed_tcb:microcode:<int>`                             | Lowest current patch level of all cores. |
| `amd_sev_snp:current_build:<int>`                             | The build number of CurrentVersion. |
| `amd_sev_snp:current_minor:<int>`                             | The major number of CurrentVersion. |
| `amd_sev_snp:current_major:<int>`                             | The major number of CurrentVersion. |
| `amd_sev_snp:committed_build:<int>`                             | The build number of CommittedVersion. |
| `amd_sev_snp:committed_build:<int>`                             | The minor version of CommittedVersion. |
| `amd_sev_snp:committed_build:<int>`                             | The major version of CommittedVersion. |
| `amd_sev_snp:launch_tcb:boot_loader:<int>`                                | Current bootloader version. SVN of PSP bootloader |
| `amd_sev_snp:launch_tcb:tee:<int>`                                | Current PSP OS version. SVN of PSP operating system |
| `amd_sev_snp:launch_tcb:snp:<int>`                                | Version of the SNP firmware. Security Version Number (SVN) of SNP firmware |
| `amd_sev_snp:launch_tcb:microcode:<int>`                             | Lowest current patch level of all cores. |
| `amd_sev_snp:signing_key_hash:<string>`  | The SIGNING_KEY SHA512. |

### Compatibility considerations

+ This plugin is designed to work with AMD SEV-SNP VMs. For more information check [this](https://developer.amd.com/sev/) documentation.

+ For more informations about the AMD SEV-SNP Node Attestor and Cloud Providers check [this](./cloud-providers.MD) documentation.

### Build

First, you need to have Golang installed.

```bash
wget https://go.dev/dl/go1.21.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
echo "export PATH=$PATH:/usr/local/go/bin" >> $HOME/.profile
source $HOME/.profile
go version 
```

Now you can build the Agent plugin using this command:
```bash
make build-agent BUILD_PATH=<PATH_TO_BUILD>

# It will generate a <PATH_TO_BUILD>/snp-agent binary, which is the agent plugin binary
# To simplify, you can set "~/" as the build path.
```
Now you can build the Server plugin using this command:

```bash
make build-server BUILD_PATH=<PATH_TO_BUILD>

# It will generate a <PATH_TO_BUILD>/snp-server binary, which is the server plugin binary
# To simplify, you can set "~/" as the build path.
```
### For testing the plugin

An AMD SEV-SNP VM is required to test this plugin. In the `amd-sev-snp` directory run this command bellow.

```
make test
```


## Acknowledgments

**This work has been financed through the Secure and Scalable Identity Provisioning (SSIP) project, a collaboration between Hewlett Packard Enterprise Brazil and the EMBRAPII unit UFCG-CEEI (Universidade Federal de Campina Grande) with the incentive of the Informatics Law (Law 8.248 from October 23rd, 1991).**
