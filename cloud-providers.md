## The AMD SEV-SNP Node Attestor and Cloud Providers

### Amazon Web Services (AWS)
On AWS, we successfully experimented with the AMD-SEV-SNP plugin enabled in the following instance flavours: 

* M6a: m6a.large | m6a.xlarge | m6a.2xlarge | m6a.4xlarge | m6a.8xlarge
* C6a: c6a.large | c6a.xlarge | c6a.2xlarge | c6a.4xlarge | c6a.8xlarge | c6a.12xlarge | c6a.16xlarge
* R6a: r6a.large | r6a.xlarge | r6a.2xlarge | r6a.4xlarge

**WARNING**: _Although the SEV-SNP plugin worked in all mentioned flavours, some AWS VMs are instantiated in hosts that do not have the EK (VCEK or VLEK) loaded. For this reason, the plugin may fail in a non-deterministic fashion._

**NOTE**: _You need to have an AMI with UEFI enabled to create instances with AMD-SEV-SNP enabled._
