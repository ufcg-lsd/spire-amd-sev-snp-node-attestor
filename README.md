# AMD SEV SNP SPIRE Plugin

An AMD SEV-SNP Node attestation plugin for SPIRE Server and SPIRE Agent.

## Server plugin: NodeAttestor "amd_sev_snp"

*Must be used in conjunction with the agent-side amd_sev_snp plugin*

The `amd_sev_snp` plugin attests to nodes that have AMD SEV-SNP technology through an out-of-band mechanism.

Plugin steps summary:

1. The plugin receives the request attestation from SPIRE Agent. . 

2. The plugin sends a nonce to SPIRE Agent that will be used to create the attestation report.

3. The plugin receives the AMD-SP endorsement key (VCEK or VLEK) and the AMD SEV-SNP attestation report from SPIRE Agent and verifies that this endorsement key was signed by the AMD root keys.

4. Then the plugin verifies if the attestation report has the nonce and it was signed by the AMD-SP endorsement key (VCEK or VLEK) provided and issues a spiffe id with the REPORT_ID and measurement from AMD SEV-SNP Guest that identify uniquely this Agent.

>The attestation report has a couple of information about the node. For more information about the attestation report see [this](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) document in section 7.3 in **Table 21. ATTESTATION_REPORT Structure**.

The SPIFFE ID produced by the server-side `amd_sev_snp` plugin is based on this information that the attestation report has.

The SPIFFE ID has the form:

```xml
spiffe://<trust-domain>/spire/agent/amd_sev_snp/chip_id/<truncated_chip_id>/measurement/<truncated_measurement>/report_id/<report_id>
```

| Configuration           | Description                                                                                                                                                                                       | Default |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `amd_cert_chain`         | ASK/ARK certificates chain provided by AMD. |         |  |

A sample configuration:

```hcl
    NodeAttestor "amd_sev_snp" {
        plugin_cmd = "<path/to/plugin_binary>"
        plugin_data {
            amd_cert_chain = "<path/to/amd_certchain>"
        }
    }
```

### Selectors

| Selector                    | Example                                                           | Description                                                                              |
|-----------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| GUEST_SVN | `amd_sev_snp:guest_svn:0`                                | The guest SVN.                                                               |
| POLICY ABI_MINOR | `amd_sev_snp:policy:abi_minor:0`                                | The guest policy. The minimum ABI minor version required for this guest to run.                                                               |
| POLICY ABI_MAJOR | `amd_sev_snp:policy:abi_major:0`                                | The guest policy. The minimum ABI major version required for this guest to run.                                                               |
| POLICY SMT | `amd_sev_snp:policy:smt:true`                                | The guest policy. <br/> false: SMT is disallowed.<br/> true: SMT is allowed.                                                              |
| POLICY MIGRATE_MA | `amd_sev_snp:policy:migrate_ma:true`                                | The guest policy. <br/> false: Association with a migration agent is disallowed. <br/> true: Association with a migration agent is allowed. |
| POLICY DEBUG | `amd_sev_snp:policy:debug:true`                                | The guest policy. <br/> false: Debugging is disallowed. <br/> true: Debugging is allowed. |
| POLICY SINGLE_SOCKET | `amd_sev_snp:policy:single_socket:true`                                | The guest policy. <br/> false: Guest can be activated on multiple sockets. <br/> false: Guest can be activated only on one socket. |
| FAMILY_ID | `amd_sev_snp:family_id:00000000000000000000000000000000`                                | The family ID provided at launch. |
| IMAGE_ID | `amd_sev_snp:image_id:00000000000000000000000000000000`                                | The image ID provided at launch. |
| VMPL | `amd_sev_snp:vmpl:0`                                | The request VMPL for the attestation report. |
| SIGNATURE_ALGO | `amd_sev_snp:signature_algo:0`                                | The signature algorithm used to sign this report. |
| CURRENT_TCB BOOT_LOADER | `amd_sev_snp:current_tcb:boot_loader:3`                                | • Current bootloader version <br/> • SVN of PSP bootloader |
| CURRENT_TCB TEE | `amd_sev_snp:current_tcb:tee:0`                                | • Current PSP OS version <br/> • SVN of PSP operating system |
| CURRENT_TCB SNP | `amd_sev_snp:current_tcb:snp:8`                                | • Version of the SNP firmware <br/> • Security Version Number (SVN) of SNP firmware |
| CURRENT_TCB MICROCODE | `amd_sev_snp:current_tcb:microcode:8`                             | Lowest current patch level of all cores. |
| PLATFORM_INFO SMT_EN | `amd_sev_snp:platform_info:smt_en:true`                             | Indicates that SMT is enabled in the system. |
| PLATFORM_INFO TSME_EN | `amd_sev_snp:platform_info:tsme_en:true`                             | Indicates that TSME is enabled in the system. |
|  SIGNING_KEY  | `amd_sev_snp:signing_key:true`                             | Encodes the key used to sign this report. <br/> 0: VCEK. <br/> 1: VLEK. <br/> 2–6: Reserved. <br/> 7: None <br/> |
|  MASK_CHIP_KEY  | `amd_sev_snp:mask_chip_key:true`                             | The value of MaskChipKey. |
|  AUTHOR_KEY_EN  | `amd_sev_snp:mask_chip_key:true`                             | Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn. |
| MEASUREMENT | `amd_sev_snp:measurement:14361f09dff2cab3f977fe28a9822dfc53815a001698cead8f78d30c7118bf3a15b0691451816a0413ff962474cec13d`                                | Launch measurement of the AMD SEV-SNP machine. |
|  HOST_DATA | `amd_sev_snp:host_data:0000000000000000000000000000000000000000000000000000000000000000`                                | Data provided by the hypervisor at launch. |
| ID_KEY_DIGEST | `amd_sev_snp:id_key_digest:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` | SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH. |
|  AUTHOR_KEY_DIGEST | `amd_sev_snp:author_key_digest:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` | SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH. Zeroes if AUTHOR_KEY_EN is 1. |
| REPORT_ID_MA | `amd_sev_snp:report_id_ma:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | Report ID of this guest’s migration agent. |
| REPORTED_TCB BOOT_LOADER | `amd_sev_snp:reported_tcb:boot_loader:3`                                | • Current bootloader version <br/> • SVN of PSP bootloader |
| REPORTED_TCB TEE | `amd_sev_snp:reported_tcb:tee:0`                                | • Current PSP OS version <br/> • SVN of PSP operating system |
| REPORTED_TCB SNP | `amd_sev_snp:reported_tcb:snp:8`                                | • Version of the SNP firmware <br/> • Security Version Number (SVN) of SNP firmware |
| REPORTED_TCB MICROCODE | `amd_sev_snp:reported_tcb:microcode:8`                             | Lowest current patch level of all cores. |
| CHIP_ID | `amd_sev_snp:chip_id:20028d4636c268b3bd525b429d333c28273cfcb63874f8cff78fa613887002990efec70c4c538bac5e084371f3d76659360a8e5157d5e7588057a715a8272dba`                             | If MaskChipId is set to 0, Identifier unique to the chip as output by GET_ID. Otherwise, set to 0h. |
| COMMITTED_TCB BOOT_LOADER | `amd_sev_snp:committed_tcb:boot_loader:3`                                | • Current bootloader version <br/> • SVN of PSP bootloader |
| COMMITTED_TCB TEE | `amd_sev_snp:committed_tcb:tee:0`                                | • Current PSP OS version <br/> • SVN of PSP operating system |
| COMMITTED_TCB SNP | `committed_tcb:snp:8`                                | • Version of the SNP firmware <br/> • Security Version Number (SVN) of SNP firmware |
| COMMITTED_TCB MICROCODE | `amd_sev_snp:committed_tcb:microcode:8`                             | Lowest current patch level of all cores. |
| CURRENT_BUILD | `amd_sev_snp:current_build:0`                             | The build number of CurrentVersion. |
| CURRENT_MINOR | `amd_sev_snp:current_minor:0`                             | The major number of CurrentVersion. |
| CURRENT_MAJOR | `amd_sev_snp:current_major:0`                             | The major number of CurrentVersion. |
| COMMITTED_BUILD | `amd_sev_snp:committed_build:0`                             | The build number of CommittedVersion. |
| COMMITTED_MINOR | `amd_sev_snp:committed_build:0`                             | The minor version of CommittedVersion. |
| COMMITTED_MAJOR | `amd_sev_snp:committed_build:0`                             | The major version of CommittedVersion. |
| LAUNCH_TCB BOOT_LOADER | `amd_sev_snp:launch_tcb:boot_loader:3`                                | • Current bootloader version <br/> • SVN of PSP bootloader |
| LAUNCH_TCB TEE | `amd_sev_snp:launch_tcb:tee:0`                                | • Current PSP OS version <br/> • SVN of PSP operating system |
| LAUNCH_TCB SNP | `amd_sev_snp:launch_tcb:snp:8`                                | • Version of the SNP firmware <br/> • Security Version Number (SVN) of SNP firmware |
| LAUNCH_TCB MICROCODE | `amd_sev_snp:launch_tcb:microcode:8`                             | Lowest current patch level of all cores. |
| SHA512 SIGNING_KEY_HASH            | `amd_sev_snp:signing_key_hash:e117dfe112354123125ba8dfe9e591da6886452561558ff595d1094fca8360a7fab565546bc94e968e1b0f8761b263790321afa7b5f469d4543210fa131401`  | The SIGNING_KEY SHA512. |

## Agent plugin: NodeAttestor "amd_sev_snp"

*Must be used in conjunction with the server-side amd_sev_snp plugin*

The `amd_sev_snp` plugin provides attestation data for a node that has the AMD SEV-SNP technology through an out-of-band mechanism.

Plugin steps summary:

1. The plugin send an attestation request to SPIRE Server.

2. The plugin receives a nonce from SPIRE Server and uses it to create an attestation report.

3. The plugin gets the AMD-SP endorsement key (VCEK or VLEK) from the AMD SEV-SNP guest and sends the attestation report with VCEK to SPIRE Server.

>The attestation report has a couple of information about the node. For more information about the attestation report see [this](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) document in section 7.3 in **Table 21. ATTESTATION_REPORT Structure**.

The SPIFFE ID produced by the server-side `amd_sev_snp` plugin is based on this information that the attestation report has.

The SPIFFE ID has the form:

```xml
spiffe://<trust-domain>/spire/agent/amd_sev_snp/chip_id/<truncated_chip_id>/measurement/<truncated_measurement>/report_id/<report_id>
```

A sample configuration:

```hcl
    NodeAttestor "amd_sev_snp" {
        plugin_cmd = "<path/to/plugin_binary>"
        plugin_data {
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

## Acknowledgments

**This work has been financed through the Secure and Scalable Identity Provisioning (SSIP) project, a collaboration between Hewlett Packard Enterprise Brazil and the EMBRAPII unit UFCG-CEEI (Universidade Federal de Campina Grande) with the incentive of the Informatics Law (Law 8.248 from October 23rd, 1991).**