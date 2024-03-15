# Instructions to obtain keys through the snpguest tool

To generate the guest report and get the `cert_chain` and the `VCEK`, we will use VirTEE's snpguest tool.

## Installing the dependencies:

```bash
sudo apt update -y
sudo apt install cargo -y
```

## Getting the snpguest tool:

```bash
git clone https://github.com/virtee/snpguest.git
cd snpguest
cargo build
sudo cp target/debug/snpguest /usr/local/bin/
cd ..
```

## Obtaining the guest report:

### Non-SVSM VMs

```bash
mkdir reports
cd reports
dd if=/dev/urandom of=reqdata.bin bs=64 count=1
sudo snpguest report ./guest_report.bin ./reqdata.bin --random
```

### SVSM VMs

```bash
mkdir reports
cd reports
sudo apt install -y make gcc uuid-dev libssl-dev tpm2-tools
sudo tpm2_nvread -C o 0x1C00002 > ./guest_report.bin
```

## Obtaining the VCEK:

To get the VCEK, run the following command:
```bash
sudo snpguest fetch vcek DER Milan ./ ../reports/guest_report.bin
sudo openssl x509 -inform der -in vcek.der -out vcek.pem
```
