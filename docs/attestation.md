# Attestation Workflow

The `amd_sev_snp` plugin attests to nodes that have AMD SEV-SNP technology through an out-of-band mechanism.

Plugin steps summary:

1. The Server receives the request attestation along with the AMD-SP endorsement key (VCEK or VLEK) from the Agent. 

2. The Server verifies if the AMD root keys signed the endorsement key, and in a positive case, it sends a nonce to the Agent. This nonce will be used to create the attestation report.

3. The Agent requests the attestation report to the AMD-SP.

4. The Server receives the attestation report and verifies if the attestation report has the proper nonce and if it was signed by the AMD-SP endorsement key (VCEK or VLEK) provided. If both verifications succeed, the Server issues an SVID with the REPORT_ID and measurement of that Node that identify uniquely this Agent.

>The attestation report has a couple of information about the node. For more information about the attestation report see [this document](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) in section 7.3 in **Table 21. ATTESTATION_REPORT Structure**.