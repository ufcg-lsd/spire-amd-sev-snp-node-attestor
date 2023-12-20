# FAQ

Here, we want to present some problems you may face while running the plugin on differents environments.

## Sumary:

[1 - Issue in obtaining the SNP report?](#1---issue-in-obtaining-the-snp-report)

[2 - Why can't the plugin fetch the EK on some public clouds?](#2---why-cant-the-plugin-fetch-the-ek-on-some-public-clouds)

[3 - Why does the cert chain check fail against my VCEK/VLEK?](#3---why-the-cert-chain-check-fails-against-my-vcekvlek)

## Questions:

#### 1 - Issue in obtaining the SNP report?

Our plugin needs to have access to the device to be able to attest the node. If you are using the SVSM approach, you need to be sure that the Agent has access to the `/dev/tpm0` device. Otherwise, when running in a non-SVSM CVM, i.e., in CVMs with access to the `/dev/sev-guest` device, be sure the Agent has access to the sev-guest device. If you run a K8S cluster over CVMs, notice that these hints are implemented by exposing the device (TPM or SNP) to the pod.

The error will appear as "panic: runtime error", and may be rose from the ```snputil.GetReportTPM()``` ou ```client.GetRawExtendedReport(device, nonce)``` functions.

#### 2 - Why can't the plugin fetch the EK on some public clouds?
    
Some CVM instances do not load the EK in the AMD-SP cache in a non-deterministic fashion. In that case, you need to provide the EK through the SPIRE Agent configuration file on the `ek_path` field.

#### 3 - Why does the cert chain check fail against my VCEK/VLEK?

You need to be sure that your machine has a VCEK or VLEK. It is possible to get machines with different EK types on the same cloud provider, so you must check if you need to load a VCEK or a VLEK on the plugin configuration.