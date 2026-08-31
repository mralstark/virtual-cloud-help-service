package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/mralstark/virtual-cloud-help-service/internal/artifactlock"
)

func main() {
	lockPath := flag.String("lock", "deploy/data-plane/artifacts.lock.json", "path to the reviewed artifact lock")
	name := flag.String("name", "", "exact artifact name from the lock")
	outputDirectory := flag.String("out-dir", ".local/artifacts", "private output directory")
	flag.Parse()

	if *name == "" {
		fmt.Fprintln(os.Stderr, "artifact-fetch: -name is required")
		os.Exit(2)
	}
	lock, err := artifactlock.Load(*lockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	artifact, err := artifactlock.Find(lock, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	path, err := artifactlock.Fetch(context.Background(), artifactlock.NewHTTPClient(), artifact, *outputDirectory)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(path)
}
