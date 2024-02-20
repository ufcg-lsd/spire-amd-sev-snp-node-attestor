# AMD SEV-SNP Quickstart

This document details how to configure and use the AMD SEV-SNP node attestor. 

We start by deploying a simple workload on a standard (non-confidential) AWS EC2 instance, using the `aws_iid` plugin to attest the node and the `Unix` workload attestor to attest the workload. Then, we show how to enforce this workload to only execute in an AMD SEV-SNP confidential instance on EC2. We show the steps to configure the `amd_sev_snp` node attestor and how to update the selectors of the node registration entry accordingly.

## Requirements
To run this demo, you must have an AWS account able to run AMD SEV-SNP VMs, and `AWS-CLI version 1.27.155`. (For more information about SEV-SNP on AWS, [click here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html))

### Installing AWS-CLI 1.27.155

Notice that if you are using another version of `AWS-CLI`, some of the commands run on this demo may not work. Be aware that you must use the `us-east-2` or `eu-west-1` regions to launch AMD SEV-SNP VMs.

```bash
sudo apt install -y python3-pip

pip3 install awscli==1.27.155 --upgrade --user

export PATH=$PATH:~/.local/bin

aws --version
# aws-cli/1.27.155 Python/3.8.10 Linux/5.15.0-91-generic botocore/1.29.155

aws configure
# AWS Access Key ID [none]:
```

## QuickStart

### 1. Launch the SPIRE Server VM on EC2

Now, let's launch a non-confidential VM on EC2 with Ubuntu 23.04 to run the SPIRE Server.

The following commands will create a new security group named "security-group-snp-demo", to allow the traffic on port 8081 on the server. Then will instantiate a VM called "spire-server-snp-demo", with 1 vCPU and 2GiB of RAM (m6a.large) included on this security group.

You must set the `KEY_PAIR_NAME` and `SSH_KEY_PATH` variables with the name of your key pair on AWS and with the path to the private part of this key on your computer respectively.

```bash
IMAGE_ID=ami-03789804238d38e80 # ubuntu-lunar-23.04 ami
INSTANCE_TYPE=m6a.large
INSTANCE_NAME=spire-server-snp-demo
SECURITY_GROUP_NAME=security-group-snp-demo
KEY_PAIR_NAME=<your_key_pair_name>
SSH_KEY_PATH=<your_ssh_private_key_path>
```

After setting the environment variables, you can run the following commands to launch a VM to run the SPIRE Server.

```bash
SECURITY_GROUP=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} --description "Security Group that enables port 8081 on SPIRE Server" | grep -o '"GroupId": *"[^"]*"' | awk -F'"' '{print $4}')

aws ec2 authorize-security-group-ingress --group-id ${SECURITY_GROUP} --protocol tcp --port 8081 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id ${SECURITY_GROUP} --protocol tcp --port 22 --cidr 0.0.0.0/0

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $IMAGE_ID \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_PAIR_NAME \
  --ebs-optimized \
  --block-device-mappings '[{"DeviceName": "/dev/sda1","Ebs": {"Encrypted": false,"DeleteOnTermination": true,"VolumeSize": 32,"VolumeType": "gp2"}}]' \
  --network-interfaces '[{"AssociatePublicIpAddress": true,"DeviceIndex": 0,"Groups": ["'"${SECURITY_GROUP}"'"]}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key="Name",Value="'"${INSTANCE_NAME}"'"}]' \
  --private-dns-name-options '{"HostnameType": "ip-name","EnableResourceNameDnsARecord": true,"EnableResourceNameDnsAAAARecord": false}' | grep -o '"InstanceId": *"[^"]*"' | awk -F'"' '{print $4}')

INSTANCE_PUBLIC_DNS=$(aws ec2 describe-instances \
    --instance-ids ${INSTANCE_ID} \
    --query 'Reservations[].Instances[].PublicDnsName' | sed -n 's/.*"\(.*\)".*/\1/p')

ssh -i ${SSH_KEY_PATH} ubuntu@${INSTANCE_PUBLIC_DNS}
```

Now that you have access to the VM, let's set up the SPIRE Server

```bash
sudo apt update  -y
sudo apt install -y build-essential

wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

echo "export PATH=$PATH:/usr/local/go/bin" >> .bashrc

wget https://github.com/spiffe/spire/releases/download/v1.8.7/spire-1.8.7-linux-amd64-musl.tar.gz
tar -xf spire-1.8.7-linux-amd64-musl.tar.gz
cd spire-1.8.7
sudo cp bin/spire-server /bin

git clone https://github.com/ufcg-lsd/spire-amd-sev-snp-node-attestor.git
cd spire-amd-sev-snp-node-attestor/
make build-server

curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o cert_chain.pem

cd ..
```

Now, you can configure the SPIRE Server with the `amd_sev_snp` and `aws_iid` plugins. Modify the `/home/ubuntu/spire-1.8.7/conf/server/server.conf` with the following configs

```conf
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "example.org"
    data_dir = "./data/server"
    log_level = "DEBUG"
    ca_ttl = "168h"
    default_x509_svid_ttl = "48h"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "./data/server/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "./data/server/keys.json"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    NodeAttestor "aws_iid" {
        plugin_data {
            access_key_id = "ACCESS_KEY_ID"
            secret_access_key = "SECRET_ACCESS_KEY"
        }
    }

    NodeAttestor "amd_sev_snp" {
        plugin_cmd = "/home/ubuntu/spire-1.8.7/spire-amd-sev-snp-node-attestor/snp-server-plugin"
        plugin_data {
            amd_cert_chain = "/home/ubuntu/spire-1.8.7/spire-amd-sev-snp-node-attestor/cert_chain.pem"
        }
    }
}
```

Remember to set the `access_key_id` and `secret_access_key` values on the `aws_iid` configurations.

Now, you can run the SPIRE Server

```bash
sudo spire-server run
```

### 2. Create entries for Agent and Workload

On a terminal in the SPIRE Server machine, run the following commands to create the identities for the SPIRE Agent and the workload

```bash
sudo spire-server entry create \
    -node \
    -spiffeID spiffe://example.org/demo/agent \
    -selector aws_iid:image:id:ami-03789804238d38e80 \
    -selector aws_iid:sg:name:security-group-snp-demo-agent

sudo spire-server entry create \
    -parentID spiffe://example.org/demo/agent \
    -spiffeID spiffe://example.org/demo/workload \
    -selector unix:uid:0
```

### 3. Launch the SPIRE Agent with aws_iid plugin

In another terminal, let's launch the other VM and run the SPIRE Agent on it

```bash
IMAGE_ID=ami-03789804238d38e80 # ubuntu-lunar-23.04 ami
INSTANCE_TYPE=m6a.large
INSTANCE_NAME=spire-agent-snp-demo
SECURITY_GROUP_NAME=security-group-snp-demo-agent
KEY_PAIR_NAME=<your_key_pair_name>
SSH_KEY_PATH=<your_ssh_private_key_path>
```

After setting the environment variables, you can run the following commands to launch a VM to run the SPIRE Agent.

```bash
SECURITY_GROUP=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} --description "Security Group that enables port 22 on SPIRE Agent" | grep -o '"GroupId": *"[^"]*"' | awk -F'"' '{print $4}')

aws ec2 authorize-security-group-ingress --group-id ${SECURITY_GROUP} --protocol tcp --port 22 --cidr 0.0.0.0/0

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $IMAGE_ID \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_PAIR_NAME \
  --ebs-optimized \
  --block-device-mappings '[{"DeviceName": "/dev/sda1","Ebs": {"Encrypted": false,"DeleteOnTermination": true,"VolumeSize": 32,"VolumeType": "gp2"}}]' \
  --network-interfaces '[{"AssociatePublicIpAddress": true,"DeviceIndex": 0,"Groups": ["'"${SECURITY_GROUP}"'"]}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key="Name",Value="'"${INSTANCE_NAME}"'"}]' \
  --private-dns-name-options '{"HostnameType": "ip-name","EnableResourceNameDnsARecord": true,"EnableResourceNameDnsAAAARecord": false}' | grep -o '"InstanceId": *"[^"]*"' | awk -F'"' '{print $4}')

INSTANCE_PUBLIC_DNS=$(aws ec2 describe-instances \
    --instance-ids ${INSTANCE_ID} \
    --query 'Reservations[].Instances[].PublicDnsName' | sed -n 's/.*"\(.*\)".*/\1/p')

ssh -i ${SSH_KEY_PATH} ubuntu@${INSTANCE_PUBLIC_DNS}
```

Now, run the following commands to configure the Agent:

```bash
sudo apt update  -y
sudo apt install -y build-essential

wget https://github.com/spiffe/spire/releases/download/v1.8.7/spire-1.8.7-linux-amd64-musl.tar.gz
tar -xf spire-1.8.7-linux-amd64-musl.tar.gz
cd spire-1.8.7
sudo cp bin/spire-agent /bin
```

Now, you can configure the SPIRE Agent with the `aws_iid` plugin. Modify the `/home/ubuntu/spire-1.8.7/conf/agent/agent.conf` with the following configs

```conf
agent {
    data_dir = "./data/agent"
    log_level = "DEBUG"
    trust_domain = "example.org"
    server_address = "SPIRE_SERVER_IP"
    server_port = 8081

    # Insecure bootstrap is NOT appropriate for production use but is ok for 
    # simple testing/evaluation purposes.
    insecure_bootstrap = true
}

plugins {
   KeyManager "disk" {
        plugin_data {
            directory = "./data/agent"
        }
    }

    NodeAttestor "aws_iid" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {
            discover_workload_path = true
        }
    }
}
```

Remember to set the `server_address` configuration to allow communication with your SPIRE Server.

Now, you can run the SPIRE Agent

```bash
sudo spire-agent run
```

### 4. Running the workload

Now that your Agent is running and received the SVID, you can run the workload

```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

echo "export PATH=$PATH:/usr/local/go/bin" >> .bashrc

git clone https://github.com/ufcg-lsd/spire-amd-sev-snp-node-attestor.git
cd spire-amd-sev-snp-node-attestor/docs/quickstart

go build quickstart_wl.go

sudo ./quickstart_wl
# SPIFFE ID obtained: spiffe://example.org/demo/workload
```

You can check that the workload has been attested, and it printed its SPIFFEID (`spiffe://example.org/demo/workload`) on the terminal.

### 5. Launch the SPIRE Agent with amd_sev_snp plugin

Now, in another terminal, let's launch the SEV-SNP confidential VM

```bash
IMAGE_ID=ami-03789804238d38e80 # ubuntu-lunar-23.04 ami
INSTANCE_TYPE=m6a.large
INSTANCE_NAME=spire-agent-snp-demo-snp
SECURITY_GROUP_NAME=security-group-snp-demo-agent-snp
KEY_PAIR_NAME=<your_key_pair_name>
SSH_KEY_PATH=<your_ssh_private_key_path>
```

After setting the environment variables, you can run the following commands to launch a VM to run the SPIRE Agent.

```bash
SECURITY_GROUP=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} --description "Security Group that enables port 22 on SPIRE Agent" | grep -o '"GroupId": *"[^"]*"' | awk -F'"' '{print $4}')

aws ec2 authorize-security-group-ingress --group-id ${SECURITY_GROUP} --protocol tcp --port 22 --cidr 0.0.0.0/0

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $IMAGE_ID \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_PAIR_NAME \
  --ebs-optimized \
  --cpu-options '{"AmdSevSnp": "enabled"}' \
  --block-device-mappings '[{"DeviceName": "/dev/sda1","Ebs": {"Encrypted": false,"DeleteOnTermination": true,"VolumeSize": 32,"VolumeType": "gp2"}}]' \
  --network-interfaces '[{"AssociatePublicIpAddress": true,"DeviceIndex": 0,"Groups": ["'"${SECURITY_GROUP}"'"]}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key="Name",Value="'"${INSTANCE_NAME}"'"}]' \
  --private-dns-name-options '{"HostnameType": "ip-name","EnableResourceNameDnsARecord": true,"EnableResourceNameDnsAAAARecord": false}' | grep -o '"InstanceId": *"[^"]*"' | awk -F'"' '{print $4}')

INSTANCE_PUBLIC_DNS=$(aws ec2 describe-instances \
    --instance-ids ${INSTANCE_ID} \
    --query 'Reservations[].Instances[].PublicDnsName' | sed -n 's/.*"\(.*\)".*/\1/p')

ssh -i ${SSH_KEY_PATH} ubuntu@${INSTANCE_PUBLIC_DNS}
```

Now, run the following commands to configure the Agent:

```bash
sudo apt update  -y
sudo apt install -y build-essential

wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

echo "export PATH=$PATH:/usr/local/go/bin" >> .bashrc

wget https://github.com/spiffe/spire/releases/download/v1.8.7/spire-1.8.7-linux-amd64-musl.tar.gz
tar -xf spire-1.8.7-linux-amd64-musl.tar.gz
cd spire-1.8.7
sudo cp bin/spire-agent /bin

git clone https://github.com/ufcg-lsd/spire-amd-sev-snp-node-attestor.git
cd spire-amd-sev-snp-node-attestor/
make build-agent

cd ..
```

Now, you can configure the SPIRE Agent with the `amd_sev_snp` plugin. Modify the `/home/ubuntu/spire-1.8.7/conf/agent/agent.conf` with the following configs

```conf
agent {
    data_dir = "./data/agent"
    log_level = "DEBUG"
    trust_domain = "example.org"
    server_address = "SPIRE_SERVER_IP"
    server_port = 8081

    # Insecure bootstrap is NOT appropriate for production use but is ok for 
    # simple testing/evaluation purposes.
    insecure_bootstrap = true
}

plugins {
   KeyManager "disk" {
        plugin_data {
            directory = "./data/agent"
        }
    }

    NodeAttestor "amd_sev_snp" {
        plugin_cmd = "/home/ubuntu/spire-1.8.7/spire-amd-sev-snp-node-attestor/snp-agent-plugin"
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {
            discover_workload_path = true
        }
    }
}
```


Remember to set the `server_address` configuration to allow communication with your SPIRE Server.

Now, you can run the SPIRE Agent

```bash
sudo spire-agent run
```

### 6. Upload the entries to use amd_sev_snp selectors

Now, let's update the Agent entry to use amd_sev_snp selectors. We'll be using measurement and policy selectors on this demo.

The measurement is an important selector because it contains information about the VM's firmware and platform TCB version.

The policy debug selector will guarantee that the VM is not allowed to run on debug mode, which would allow the host to read and modify the VM's memory. 

To discover the correct measurement to use in the selector, we will be using the [sev-snp-measure](https://github.com/virtee/sev-snp-measure) tool.

On a terminal on the SPIRE Server machine, run the following commands to generate the expected measurement for the AMD SEV-SNP VM

```bash
git clone https://github.com/virtee/sev-snp-measure.git
cd sev-snp-measure

wget https://github.com/aws/uefi/releases/download/20230516/ovmf_img.fd
SNP_MEASUREMENT=$(./sev-snp-measure.py --mode snp --vcpus=2 --vmm-type=ec2 --ovmf=ovmf_img.fd)
```

```bash
sudo spire-server entry show
# Found 2 entries
# Entry ID         : 8897ac63-bf61-4cdc-b033-aa4166c4f0c2
# SPIFFE ID        : spiffe://example.org/demo/agent
# Parent ID        : spiffe://example.org/spire/server
# Revision         : 0
# X509-SVID TTL    : default
# JWT-SVID TTL     : default
# Selector         : aws_iid:image:id:ami-03789804238d38e80
# Selector         : aws_iid:sg:name:security-group-snp-demo-agent

# Entry ID         : 22b3321f-6bd6-4a9e-9101-000b38514e08
# SPIFFE ID        : spiffe://example.org/demo/workload
# Parent ID        : spiffe://example.org/demo/agent
# Revision         : 0
# X509-SVID TTL    : default
# JWT-SVID TTL     : default
# Selector         : unix:uid:0
```

Find the Agent entry and get its ID to update the entry. In this example, the ID is `8897ac63-bf61-4cdc-b033-aa4166c4f0c2`.

```bash
ENTRY_ID=<ENTRY_ID>
sudo spire-server entry update \
    -entryID ${ENTRY_ID} \
    -parentID spiffe://example.org/spire/server \
    -spiffeID spiffe://example.org/demo/agent \
    -selector amd_sev_snp:measurement:${SNP_MEASUREMENT} \
    -selector amd_sev_snp:policy:debug:false
```

### 7. Running the workload on the confidential VM

Now, on the SEV-SNP VM terminal, let's run the workload:

```bash
cd spire-amd-sev-snp-node-attestor/docs/quickstart

go build quickstart_wl.go

sudo ./quickstart_wl
# SPIFFE ID obtained: spiffe://example.org/demo/workload
```

You can now go to the terminal on the non-confidential VM and try to run the workload again, the workload is no longer allowed to attest there.

### 8. Cleaning up

Now, you can run the following commands to remove the VMs and the Security Groups that you've created. You must wait until the VMs are terminated before deleting the security groups.

```bash
query=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=*-snp-demo*" | grep InstanceId)
instance_ids=($(echo "$query" | grep -oP 'InstanceId": "\K[^"]+' | tr -d ','))

for id in "${instance_ids[@]}"; do
  aws ec2 terminate-instances --instance-ids ${id}
done

aws ec2 delete-security-group --group-name security-group-snp-demo
aws ec2 delete-security-group --group-name security-group-snp-demo-agent
aws ec2 delete-security-group --group-name security-group-snp-demo-agent-snp
```

### Conclusions

With this demonstration, we can see how simple is to migrate a workload from a non-confidential to a confidential VM. Simply updating the Agent's entry to which the workload is associated to use AMD SEV-SNP selectors.
