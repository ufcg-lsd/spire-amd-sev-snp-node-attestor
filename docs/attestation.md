# Attestation Workflow

The main idea of the AMD SEV-SNP Node Attestation plugin is relying on information provided on the Attestation Report supplied by the AMD-SP to issue the SVID of the Agent.

The overall plugin workflow can be described in the following steps:

1. The Server receives an attestation request from the Agent. 
2. The Server requests an Attestation Report and the EK (VCEK/VLEK) to the Agent, providing a nonce.
3. The Agent obtains the EK, and the Attestation Report. The nonce will be used for freshness purposes.
4. The Server receives the EK and the Attestation Report. It verifies: i) if the EK was generated from AMD root keys; ii) if the Attestation Report was signed with the provided EK; iii) if the nonce returned is correct. If these verifications succeed, the Server issues an SVID to the Agent.

Notice, however, that this workflow may be slightly different depending on which environment the SEV-SNP VM is running. Actually, what differs is the strategy to obtain and validate the attestation report.

1. Sev-guest device: on-premise, AWS, GCP
2. vTPM provided through SVSM for Azure 
3. vTPM provided through SVSM for on-premise (WIP)

To sum up, the AMD SEV-SNP plugin works in 5 configurations: 1) On-premise without support to SVSM; 2) On-premise with support to SVSM; 3) AWS; 4) Azure; 5) GCP.
For details on configuring the Agent to run the plugin in cloud providers, refer to [this documentation](cloud-providers.md).

The three strategies to obtain and validate the Attestation Report are detailed next in the context of the overall attestation workflow.

## Sev-guest device (on-premise, AWS, GCP)

```mermaid
sequenceDiagram
    participant AMDSP as AMD-SP
    participant Agent as Agent in CVM
    participant Server as Server
    Agent->>Server: Request SVID
    activate Server
    Server->>Agent: Request Attestation Report<br/> providing the nonce
    activate Agent
    alt ek is in file system        
        Agent->>Agent: load EK
    else
        Agent->>AMDSP: get EK
        activate AMDSP        
        AMDSP-->>Agent: EK
        deactivate AMDSP
    end
    Agent->>AMDSP: Request Attestation Report<br/>providing the nonce
    activate AMDSP
    AMDSP-->>Agent: Attestation Report (nonce included)
    deactivate AMDSP
    Agent-->>Server: EK + Attestation Report (nonce included)
    deactivate Agent
    Note right of Server: 1) Verify nonce <br/> 2) Verify the EK against AMD cert chain <br/> 3) Verify report signature against AMD EK
    Server->>Server: 
    Server-->>Agent: SVID
    deactivate Server
```

## vTPM provided through SVSM for Azure 

```mermaid
sequenceDiagram
    participant HCL as HCL<br/>SVSM-vTPM
    participant Azure as Azure-Server
    participant Agent as Agent in CVM
    participant Server as Server
    Agent->>Server: Request SVID
    activate Server
    Server->>Agent: Request Attestation Report<br/> providing the nonce
    activate Agent
    alt ek is in file system        
        Agent->>Agent: load EK
    else
        Agent->>Azure: get EK
        activate Azure        
        Azure-->>Agent: EK
        deactivate Azure
    end
    Agent->>HCL: Request Attestation Report and AK
    activate HCL
    HCL-->>Agent: AK + Attestation Report
    deactivate HCL
    Agent->>HCL: Quote + Nonce
    activate HCL               
        HCL-->>Agent: Quote (nonce included)
    deactivate HCL
    Agent-->>Server: EK + Attestation Report + AK + Quote (nonce included)
    deactivate Agent
    Note right of Server: 1) Validate Quote against signature, AK and nonce <br/> 2) Verify binding between AK and Attestation Report <br/>3) Verify the EK against AMD cert chain <br/> 4) Verify report signature against AMD EK
    Server-->>Agent: SVID
    deactivate Server
```

***HCL is the VPML 0 in the Azure architecture, where vTPM is located***

## vTPM provided through SVSM for on-premise

```mermaid
sequenceDiagram
    participant HCL as HCL<br/>SVSM-vTPM
    participant Agent as Agent in CVM
    participant Server as Server
    Agent->>Server: Request SVID
    activate Server
    Server->>Agent: Request Registration SVSM
    activate Agent
    Agent->>Agent: load AMD EK from file system 
    Agent->>HCL: Request Attestation Report, TPM EK and TPM AIK
    activate HCL
    HCL-->>Agent: Attestation Report, AMD EK, TPM EK and TPM AIK 
    deactivate HCL
    Agent-->>Server: Registration SVSM data(Attestation Report, AMD EK, TPM EK and TPM AIK)
    deactivate Agent
    Note right of Server: 1) Verify if the attestation report contains TPM EK<br/>2) Create a challenge using the TPM MakeCredential<br/> function with a secret, AIK and TPM EK.
    Server->>Agent: Request Attestation SVSM providing challenge and nonce
    activate Agent
    Agent->>HCL: Request ActivateCredential for challenge
    activate HCL
    HCL-->>Agent: Retrieve the SVSM-vTPM challenge secret
    deactivate HCL
    Agent->>HCL: Request Quote with nonce
    activate HCL
    HCL-->>Agent: Quote (nonce included) signed by TPM AIK
    deactivate HCL
    Agent-->>Server: Response Attestation SVSM (challenge secret and Quote with nonce)
    deactivate Agent
    Note right of Server: 1) Verify if secret it is the same sent <br/> 2) Verify the Quote against TPM AIK and nonce <br/> 3) Verify the AMD EK against AMD cert chain <br/> 4) Verify report signature against AMD EK
    Server-->>Agent: SVID
    deactivate Server

```