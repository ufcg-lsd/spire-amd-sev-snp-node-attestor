# AMD SEV-SNP Selectors

The complete list of selectors and their descriptions is presented below.

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
| `amd_sev_snp:fw_version:updated` | If the current_tcb[SVN] >= min_fw_version value configured on server <br/> See [this docs](./FAQ.md#4---how-can-i-set-the-min_fw_version-on-server-conf) to learn how to set this value |
