## The AMD SEV-SNP Node Attestor and Cloud Providers

### Amazon Web Services (AWS)

We successfully executed the AMD-SEV-SNP plugin in the following flavours: 

* M6a: m6a.large | m6a.xlarge | m6a.2xlarge | m6a.4xlarge | m6a.8xlarge
* C6a: c6a.large | c6a.xlarge | c6a.2xlarge | c6a.4xlarge | c6a.8xlarge | c6a.12xlarge | c6a.16xlarge
* R6a: r6a.large | r6a.xlarge | r6a.2xlarge | r6a.4xlarge

Notice that although the SEV-SNP plugin worked in all mentioned flavours, some AWS VMs are instantiated in hosts that do not have the EK loaded in the AMD-SP cache. For this reason, we recommend specifying the `ek_path` in the agent conf file instead of rely on the plugin feature of obtaining it from the AMD-SP cache. Otherwise, the attestation may fail in a non-deterministic fashion.

**NOTE**: _You need to have an AMI with UEFI enabled to create instances with AMD SEV-SNP enabled._

### Google Cloud Platform (GCP)

To instantiate VMs with AMD-SEV-SNP enabled on GCP, it is necessary to request access to the private preview of your GCP project. We executed the plugin on the N2D instance flavors. Notice that AMD SEV-SNP VMs are only available in specific regions and zones: us-central1, europe-west4, and asia southeast1.

To this date (05/11/2023), the GCP is not providing the Endorsement Key (EK) in the AMD-SP cache. Therefore, running the plugin on GCP requires specifying the `ek_path` in the agent conf file. To retrieve the EK, refer to the [snpguest tool](https://github.com/virtee/snpguest#). Alternatively, you may refer to [this simple tutorial](snpguest.md) we created.

### Azure 

To instantiate VMs with AMD-SEV-SNP enabled on Azure, it is necessary to use the `az cli` and Ubuntu images (Ubuntu 20.04, Ubuntu 22.04). We created a new attestation flow to Azure confidential VM once they do not expose the `sev-guest` device. Notice that AMD SEV-SNP VMs are only available in specific regions and zones. We use `West US` to deploy the VMs.

To this date (05/11/2023), Azure is not providing the Endorsement Key (EK) in the cache. Therefore, running the plugin on Azure requires specifying the `ek_path` in the agent conf file or letting the plugin download the EK by itself. To retrieve the EK, follow this Azure [documentation](https://github.com/Azure/confidential-computing-cvm-guest-attestation/blob/main/cvm-guest-attestation.md).