// pilot-check verifies provider inventory without modifying a server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/providers/timeweb"
)

func main() {
	if err := run(os.Args[1:], os.Getenv("TWC_TOKEN"), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, token string, output io.Writer) error {
	flags := flag.NewFlagSet("pilot-check", flag.ContinueOnError)
	id := flags.Int64("server-id", 0, "existing Timeweb Cloud server ID (required)")
	zone := flags.String("zone", "fra-1", "expected availability zone")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *id <= 0 || *zone == "" {
		return errors.New("use pilot-check -server-id ID [-zone fra-1]; supply TWC_TOKEN in the environment")
	}
	client, err := timeweb.NewClient(token)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, err := client.GetServer(ctx, *id)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(server); err != nil {
		return err
	}
	if server.Status != "on" {
		return errors.New("pilot blocked: server is not running")
	}
	if server.AvailabilityZone != *zone {
		return errors.New("pilot blocked: server is outside the expected availability zone")
	}
	if len(server.PublicIPs) == 0 {
		return errors.New("pilot blocked: no public IP is assigned")
	}
	fmt.Fprintln(output, "Provider inventory passed. SSH, VPN installation, firewall and client transfer checks are still required.")
	return nil
}
