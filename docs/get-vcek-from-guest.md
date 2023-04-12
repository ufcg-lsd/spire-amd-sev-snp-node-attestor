# How to get the VCEK from the SEV-SNP Guest

First of all, let's clone and build the [sev-tool](https://github.com/AMDESE/sev-tool) in the host machine. You can follow the steps in the sev-tool repo to build it.

**IMPORTANT**: *Notice that the binary of sev-tool will be builted in `src/`.*

After you've installed the sevtool, let's run:

```sh
sudo sevtool --export_cert_chain_vcek
```

Now, let's copy the vcek.pem to the guest, first let's run the following command:

```sh
ip address | grep virbr

# 6: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default qlen 1000
#     inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
# 7: virbr0-nic: <BROADCAST,MULTICAST> mtu 1500 qdisc fq_codel master virbr0 state DOWN group default qlen 1000
```

Search for the `virbr0` network interface and copy it's ipv4 address.

Now, from the guest VM, you can use `scp` command to copy the `vcek.pem` to the VM.

```bash
scp <your_user>@<virbr0_id_address>:/home/<your_user>/<path_to_vcek.pem> ./
```

Notice that you must have to include your VM public key into the authorized_keys in the host depending on the permissions of ssh.
