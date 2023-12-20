# AMD SEV-SNP SPIRE Plugin

The AMD SEV-SNP node attestation plugin can attest on-premise and public cloud providers' SEV-SNP VMs. 

- For attestation workflow details, refer to [this documentation](./docs/attestation.md).
- To ensure disk integrity and confidentiality, refer to [this documentation](./docs/disk-integrity-confidentiality.md).
- For information about running the plugin in public cloud providers, refer to [this documentation](./docs/cloud-providers.md).
- For details about the SEV-SNP technology, refer to [this documentation](./docs/amd-sev-snp.md).
- [Frequented Asked Questions (FAQ)](./docs/FAQ.md)

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

The `amd_cert_chain` field refers to the ASK/ARK certificates chain provided by AMD.
To get one of `amd_cert_chain` you can use the commands below:

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
        ek_path = "<path/to/ek>"
    }
}
```

The `ek_path` field refers to the VCEK or VLEK provided by the cloud provider. This field is optional, if it is not provided the plugin will try to obtain the VCEK or VLEK from the AMD-SP cache. If the VCEK or VLEK is not in the cache, the plugin will try to load it from the file system through the `ek_path` field. To obtain the VCEK/VLEK from the AMD Key Distribution System (KDS) check [this documentation](./docs/snpguest.md).

### Selectors

The main selectors are presented below. 
To check the complete list of selectors refer to [this documentation](./docs/selectors.md).

|Selector                                                           | Description                                                                              |
|-------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| `amd_sev_snp:measurement:<string>`                                | Launch measurement of the AMD SEV-SNP machine. |
| `amd_sev_snp:chip_id:<string>`                             | If MaskChipId is set to 0, Identifier unique to the chip as output by GET_ID. Otherwise, set to 0h. |
| `amd_sev_snp:policy:abi_minor:<int>`                                | The guest policy. The minimum ABI minor version required for this guest to run.                                                               |
| `amd_sev_snp:policy:abi_major:<int>`                                | The guest policy. The minimum ABI major version required for this guest to run.                                                               |
| `amd_sev_snp:policy:smt:<bool>`                                | The guest policy. <br/> false: SMT is disallowed.<br/> true: SMT is allowed.                                                              |
| `amd_sev_snp:policy:migrate_ma:<bool>`                                | The guest policy. <br/> false: Association with a migration agent is disallowed. <br/> true: Association with a migration agent is allowed. |
| `amd_sev_snp:policy:debug:<bool>`                                | The guest policy. <br/> false: Debugging is disallowed. <br/> true: Debugging is allowed. |
| `amd_sev_snp:policy:single_socket:<bool>`                                | The guest policy. <br/> false: Guest can be activated on multiple sockets. <br/> false: Guest can be activated only on one socket. |

### Build and Test

Build and test instructions are detailed in [this documentation](./docs/build.md).

## Acknowledgments

**This work has been financed through the Secure and Scalable Identity Provisioning (SSIP) project, a collaboration between Hewlett Packard Enterprise Brazil and the EMBRAPII unit UFCG-CEEI (Universidade Federal de Campina Grande) with the incentive of the Informatics Law (Law 8.248 from October 23rd, 1991).**
