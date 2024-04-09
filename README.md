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
        cert_chains = ["<path/to/cert_chain1>", "<path/to/cert_chain2>"]
        crl_urls = ["<vcek_website_url1>", "<vcek_website_url2>"]
        insecure_crl = false
        min_fw_version = "<hex_value>"
    }
}
```

The `cert_chains` field refers to the ASK/ARK certificates chain provided by AMD.
To get these cert chains for Milan processors you can use the commands below:

```bash
# VLEK
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o vlek_cert_chain.pem
# VCEK
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o vcek_cert_chain.pem
```

The `crl_urls` field refers to ways of obtaining the Certificate Revocation List (CRL). With this configuration set, you guarantee that it will not be possible to use a certificate revoked by the issuing entity. To replace the url parameter you can use one of the URLs below:

```bash
# VLEK
https://kdsintf.amd.com/vlek/v1/Milan/crl
# VCEK
https://kdsintf.amd.com/vcek/v1/Milan/crl
```

If `insecure_crl` option is set to true, the CRL verification will be skipped. By default, this field is set to false. 

A sample configuration:

```hcl
NodeAttestor "amd_sev_snp" {
    plugin_cmd = "/home/ubuntu/snp-server-plugin"
    plugin_data {
        cert_chains = [
            "/home/ubuntu/vlek_cert_chain.pem",
            "/home/ubuntu/vcek_cert_chain.pem"
            ]
        crl_urls = [
            "https://kdsintf.amd.com/vlek/v1/Milan/crl",
            "https://kdsintf.amd.com/vcek/v1/Milan/crl"
            ]
        min_fw_version = "0x12"
    }
}
```


### Agent Configuration

```hcl
NodeAttestor "amd_sev_snp" {
    plugin_cmd = "<path/to/plugin_binary>"
    plugin_data {
        ek_path = ""
    }
}
```

The `ek_path` field refers to the VCEK or VLEK public key present on the AMD processor, which the private part signs the attestation report. This field is optional, if it is not provided the plugin will obtain the VCEK or VLEK along with the report. If it is provided, the plugin will load it from the file system through the `ek_path` field. Notice that in some cases, the plugin will not be able to retrieve the EK from the processor:

* If you are running a VM on-premise with SVSM;
* If the key is not loaded on the processor's shared memory.

In this case, the `ek_path` field must be provided. To obtain the VCEK/VLEK public key from the AMD Key Distribution System (KDS) check [this documentation](./docs/snpguest.md).

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
| `amd_sev_snp:fw_version:updated` | If the current_tcb[SVN] >= min_fw_version value configured on server <br/> See [this docs](./FAQ.md#4---how-can-i-set-the-min_fw_version-on-server-conf) to learn how to set this value |

### Build and Test

Build and test instructions are detailed in [this documentation](./docs/build.md).

## Acknowledgments

**This work has been financed through the Secure and Scalable Identity Provisioning (SSIP) project, a collaboration between Hewlett Packard Enterprise Brazil and the EMBRAPII unit UFCG-CEEI (Universidade Federal de Campina Grande) with the incentive of the Informatics Law (Law 8.248 from October 23rd, 1991).**
