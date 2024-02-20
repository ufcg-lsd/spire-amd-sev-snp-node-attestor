package main

import (
	"context"
	"fmt"
	"log"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const socketPath = "unix:///tmp/spire-agent/public/api.sock"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatal(fmt.Errorf("unable to create X509Source: %w", err))
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to fetch SVID: %w", err))
	}

	fmt.Println("SPIFFE ID obtained: " + svid.ID.String())
}
