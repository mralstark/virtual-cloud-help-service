package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
	"github.com/mralstark/virtual-cloud-help-service/internal/signingkey"
)

func main() {
	log.SetFlags(0)
	privatePath := flag.String("private-out", "", "new private key output path")
	publicPath := flag.String("public-out", "", "new public key output path")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}
	publicKey, err := signingkey.GenerateFiles(*privatePath, *publicPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stdout, "generated manifest key %s\n", manifest.KeyID(publicKey))
}
