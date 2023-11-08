# Instructions to obtain keys through the snpguest tool

To generate the guest report and get the `cert_chain` and the `vcek`, we will use VirTEE's snpguest tool.

Installing the dependencies:
```bash
sudo apt update -y
sudo apt install cargo -y
```

Getting the snpguest tool:
```bash
git clone https://github.com/virtee/snpguest.git
cd snpguest
cargo build
sudo cp target/debug/snpguest /usr/local/bin/
cd ..
```
Obtaining the guest report:
```bash
mkdir reports
cd reports
dd if=/dev/urandom of=reqdata.bin bs=64 count=1
sudo snpguest report ./guest_report.bin ./reqdata.bin --random
```
To see the report in a human-readable format, run the following command:
```bash
sudo snpguest display report ./guest_report.bin
```
To get the `cert_chain`, run the following command:
```bash
cd ..
mkdir certs
cd certs
sudo curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o cert_chain.pem
```
Getting CA's, ARK and ASK:
```bash
sudo snpguest fetch ca PEM Milan ./
```
To get the vcek, run the following command:
```bash
sudo snpguest fetch vcek DER Milan ./ ../reports/guest_report.bin
sudo openssl x509 -inform der -in vcek.der -out vcek.pem
```
To validate the certs, run the following command:
```bash
sudo snpguest verify certs ./
# The AMD ARK was self-signed!
# The AMD ASK was signed by the AMD ARK!
# The VCEK was signed by the AMD ASK!
```
To validate the guest report, run the following command:
```bash
sudo snpguest verify attestation ./ ../reports/guest_report.bin
# Reported TCB Boot Loader from certificate matches the attestation report.
# Reported TCB TEE from certificate matches the attestation report.
# Reported TCB SNP from certificate matches the attestation report.
# Reported TCB Microcode from certificate matches the attestation report.
# Chip ID from certificate matches the attestation report.
# VCEK signed the Attestation Report!
```
