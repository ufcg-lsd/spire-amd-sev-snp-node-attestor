# Deployment and Testing

## Build

Install Golang and build the server and agent plugin binaries with the makefile provided.

```bash
wget https://go.dev/dl/go1.21.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
echo "export PATH=$PATH:/usr/local/go/bin" >> $HOME/.profile
source $HOME/.profile
go version 

make build-agent BUILD_PATH=<PATH_TO_BUILD>
make build-server BUILD_PATH=<PATH_TO_BUILD
```

## Tests

In the `amd-sev-snp` directory run this command.

```
make test
```