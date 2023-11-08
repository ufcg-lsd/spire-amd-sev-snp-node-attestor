# AMD SEV-SNP

AMD SEV-SNP (Secure Encrypted Virtualization-Scalable Nested Paging) is a set of hardware-based security features designed to enhance the security of virtualized environments [[4](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)]. It extends both the AMD Secure Encrypted Virtualization (SEV) technology, which provides hardware-based memory encryption for VMs to isolate them from the hypervisor [[1](https://developer.amd.com/sev/)], and SEV-Encrypted State (SEV-ES), which adds additional protection for CPU register state as an extension of SEV [[3](https://www.amd.com/system/files/TechDocs/Protecting%20VM%20Register%20State%20with%20SEV-ES.pdf)].

The main difference between AMD SEV/SEV-ES and AMD SEV-SNP is the strong memory integrity protection present on SEV-SNP that helps prevent malicious hypervisor-based attacks, such as data replay and memory re-mapping. The fundamental concept behind SEV-SNP integrity is that whenever a VM accesses an encrypted memory page, it must retrieve the value it previously wrote. If it reads a different value, an exception must be thrown [[4](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)].

## Threat Model for AMD SEV-SNP Confidential VMs

The threat model for Confidential Computing assumes a highly powerful attacker with privileges to access and manipulate all software layers of the infrastructure, including the operating systems, hypervisors, and cloud computing platforms where confidential workloads are running. Regarding the host machine and its software stack, the attacker may be able to steal cryptographic keys and sensitive data, modify application code or binaries, and launch various types of attacks, such as side-channel attacks. [[4](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)]

Under SEV-SNP, as with SEV and SEV-ES, the AMD System-On-Chip (SoC) hardware, the AMD Secure Processor (AMD-SP), and the VM itself are all treated as fully trusted, while all other CPU software components, PCI devices, and operators of these are treated as entirely untrusted. This includes the BIOS on the host system, the hypervisor, device drivers, and other VMs. This means that these components are assumed to be malicious, potentially conspiring with other untrusted components to compromise the security guarantees of a SEV-SNP VM.

![Threat Model](../RFC/Group%201.png)

(Figure from [[4](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)])

To enable third parties to have confidence in the VM's state, the SEV-SNP provides a mechanism to attest integrity of the VM's and its environment (confirming it is indeed a AMD SEV-SNP VM). This is done by generating an Attestation Report that reflects the VM's context, including policy information and measurements taken by the AMD-SP during launch. Through measurement hashes in the Attestation Reports, third parties can verify, for example, if the VM has been launched with the expected state (e.g., a specific version of Linux Kernel, the expected Initramfs that includes disk integrity mechanisms). In addition, other information in the Attestation Report reflect other configuration options, for example, if this VM is allowed to run in debug mode. These Attestation Reports are described next.

## Chain of Trust

To build a chain of trust between the AMD-SP and the guest VM that remote parties can validate, the AMD-SP provides a protected path through which the guest VM can request Attestation Reports on their behalf at any time. When the guest asks for a report, it supplies 512 bits of arbitrary data to be included in the report. The resulting report will contain this data alongside identity information about the guest and the host where it is running. The report can be signed by a Versioned Chip Endorsement Key (VCEK), an attestation signing key derived from chip-unique secrets, and a TCB (Trusted Computing Base) version, signed by the AMD Root Keys and kept inside the AMD-SP with no access by users. The report may also be signed by a Versioned Loaded Endorsement Key (VLEK), derived from a seed maintained by the AMD Key Derivation Service (KSD) [[5](https://www.amd.com/system/files/TechDocs/56860.pdf)]. The third-party should verify the authenticity of the report based on its signature. A successful signature verification proves that the 512 bits of guest data supplied in the report came from the guest whose identity is described.

## Attestation Report

The purpose of the Attestation Report is to allow the VM to prove to third parties that it is confidential and has been configured in a trustable state with no tampering. The following table describes the Attestation Report structure [[5](https://www.amd.com/system/files/TechDocs/56860.pdf)]:

| Name              | Description                  |
|-------------------|------------------------------|
| POLICY          | The guest policy ([see below](#policy))                                                                                                                  |
| MEASUREMENT     | The measurement calculated at launch ([see below](#launch-measurement))                                                                                              |
| REPORT_DATA       | Guest-provided data                                                                                                                 |
| VERSION           | Version number of the Attestation Report (set to 0x02 for [this](https://www.amd.com/system/files/TechDocs/56860.pdf) specification) |
| GUEST_SVN         | The guest Secure Version Number (SVN)                                                                                               |
| FAMILY_ID         | The family ID provided at launch                                                                                                    |
| IMAGE_ID          | The image ID provided at launch                                                                                                     |
| VMPL              | The request Virtual Machine Privilege Level (VMPL) for the Attestation Report                                                       |
| SIGNATURE_ALGO    | The signature algorithm used to sign the report                                                       |
| CURRENT_TCB       | Current TCB ([see below](#tcb-version))                                                                                                                        |
| PLATFORM_INFO     | Information about the platform (indicates if TSME or SMT are enabled in the system)                                                 |
| SIGNING_KEY       | Encodes the key used to sign the report (0: VCEK, 1: VLEK, 2–6: Reserved, 7: None)                                                   |
| MASK_CHIP_KEY     | The value of MaskChipKey                                                                                                            |
| AUTHOR_KEY_EN     | Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST (set to the value of GCTX.AuthorKeyEn)                   |
| HOST_DATA         | Data provided by the hypervisor at launch                                                                                           |
| ID_KEY_DIGEST     | SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH                                          |
| AUTHOR_KEY_DIGEST | SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH (zeros if AUTHOR_KEY_EN is 1)   |
| REPORT_ID         | Report ID of the guest                                                                                                              |
| REPORT_ID_MA      | Report ID of the guest’s migration agent                                                                                            |
| REPORTED_TCB      | Reported TCB version used to derive the VCEK that signed this report                                                                |
| CHIP_ID           | If MaskChipId is set to 0, identifier unique to the chip as output by GET_ID, otherwise, set to 0                                   |
| COMMITTED_TCB     | Committed TCB                                                                                                                       |
| CURRENT_BUILD     | The build number of CurrentVersion                                                                                                  |
| CURRENT_MINOR     | The minor number of CurrentVersion                                                                                                  |
| CURRENT_MAJOR     | The major number of CurrentVersion                                                                                                  |
| COMMITTED_BUILD   | The build number of CommittedVersion                                                                                                |
| COMMITTED_MINOR   | The minor version of CommittedVersion                                                                                               |
| COMMITTED_MAJOR   | The major version of CommittedVersion                                                                                               |
| LAUNCH_TCB        | The Current TCB at the time the guest was launched or imported                                                                      |
| SIGNATURE         | Signature of bytes 0x000 to 0x29F (inclusive) of this report                                                                          |

The Attestation Report is signed by the private part of the VCEK/VLEK, which is located inside the AMD-SP. The public part of the VCEK/VLEK can be used to verify the signature, and its authenticity can be verified against the AMD Certificate Chain to ensure that it is valid. Therefore, we can guarantee that the report was generated inside an AMD-SP, as it is the only entity with access to the VCEK/VLEK private part.

Moreover, the user can include 512 bits of data in the Attestation Report, which ensures its freshness. By doing this, we can trust that (1) the Attestation Reports given by a VM have been freshly generated in response to the current request, and (2) the report was generated by an authentic AMD-SP (due to its signature).

## Platform Info

The platform info structure details configurations about the platform. It is structured as follows.

| Bit(s) | Name      | Description  |
|--------|-----------|--------------|
| 63:2   |     -     | Reserved |
| 1      | TSME_EN   | Indicates that Transparent Secure Memory Encryption (TSME) is enabled in the system |
| 0      | SMT_EN    | Indicates that Simultaneous Multithreading (SMT) is enabled in the system |

## Policy

The policy parameters refer to the set of rules that govern the behavior of the VM, for example, if the VM allows or not debug mode or if it is allowed to run in a platform with Simultaneous Multithreading (SMT) enabled. In the Attestation Report, the policy field is represented as 64 bits of data and is structured as follows [[5](https://www.amd.com/system/files/TechDocs/56860.pdf)]:

| Bit(s) | Name            | Description                                                                                             |
|--------|-----------------|---------------------------------------------------------------------------------------------------------|
| 63:21  |        -        | Reserved, must be zero                                                                                 |
| 20     | `SINGLE_SOCKET` | 0: Guest can be activated on multiple sockets / 1: Guest can be activated only on single socket machines           |
| 19     | `DEBUG`         | 0: Debugging is disallowed / 1: Debugging is allowed                                                   |
| 18     | `MIGRATE_MA`    | 0: Association with a migration agent is disallowed / 1: Association with a migration agent is allowed |
| 17     |        -        | Reserved, must be zero                                                                                 |
| 16     | `SMT`           | 0: SMT is disallowed / 1: SMT is allowed                                                               |
| 15:8   | `ABI_MAJOR`     | The minimum ABI major version required for this guest to run                                           |
| 7:0    | `ABI_MINOR`     | The minimum ABI minor version required for this guest to run                                           |

## TCB Version

The TCB_VERSION is a structure containing the security version numbers of the components in the SNP firmware's trusted computing base (TCB). A TCB_VERSION is associated with each image of firmware. The TCB_VERSION structure is described below:

| Bit(s) | Name            | Description                                                                                             |
|--------|-----------------|---------------------------------------------------------------------------------------------------------|
| 63:56  |   `MICROCODE`   | Lowest current patch level of all cores |
| 55:48  | `SNP`           | Version of the SNP firmware <br/>Security Version Number (SVN) of SNP firmware |
| 47:16  | `-`             | Reserved                |
| 15:8   | `TEE`           | Current Platform Security Processor (PSP) OS version, SVN of PSP operating system |
| 7:0    | `BOOT_LOADER`   | Current bootloader version, SVN of PSP bootloader |

## Launch Measurement

The Attestation Report also contains a Launch Measurement of the guest, which is calculated as [[6](https://www.amd.com/system/files/TechDocs/56860.pdf)]:

```
HMAC(0x04 || API_MAJOR || API_MINOR || BUILD || GCTX.POLICY || GCTX.LD || MNONCE; GCTX.TIK)
```

Where "||" represents concatenation. GCTX represents the guest context and the GCTX.LD is a hash digest of all plaintext data imported into the guest at boot, and how this value is calculated depends on the hypervisor. For QEMU, it can be calculated as:

```
SHA256(firmware_blob || kernel_hashes_blob || vmsas_blob)
```

Where:

* `firmware_blob` is the content of the entire firmware flash file (for example, OVMF.fd). Note that you must build a stateless firmware file that does not use an NVRAM store because the NVRAM area is not measured, and therefore, using firmware that uses a state from an NVRAM store is not secure.

* If kernel is used, and _kernel-hashes=on_, then `kernel_hashes_blob` is the content of PaddedSevHashTable (including the zero padding), which itself includes the hashes of kernel, initrd, and cmdline that are passed to the guest. 

* If SEV-ES is enabled (_policy & 0x4 != 0_), `vmsas_blob` is the concatenation of all VMSAs of the guest vcpus. Each VMSA is 4096 bytes long; its content is defined inside Linux kernel code as struct vmcb_save_area, or in AMD APM Volume 2 ([APMVOL2](https://www.amd.com/system/files/TechDocs/24593.pdf)) Table B-2: VMCB Layout, State Save Area.

## References

* [1] AMD Secure Encrypted Virtualization (SEV) <https://developer.amd.com/sev/>

* [2] AMD Memory Encryption. <https://amd.wpenginepowered.com/wordpress/media/2013/12/AMD_Memory_Encryption_Whitepaper_v9-Public.pdf>

* [3] Protecting VM Register State With SEV-ES. <https://www.amd.com/system/files/TechDocs/Protecting%20VM%20Register%20State%20with%20SEV-ES.pdf>

* [4] AMD SEV-SNP: Strengthening VM Isolation with Integrity Protection and More. <https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf>

* [5] SEV Secure Nested Paging Firmware ABI Specification. <https://www.amd.com/system/files/TechDocs/56860.pdf>

* [6] Secure Encrypted Virtualization API Version 0.24. <https://www.amd.com/system/files/TechDocs/56860.pdf>