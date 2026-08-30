package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
	"github.com/mralstark/virtual-cloud-help-service/internal/signingkey"
)

const maxGrantFileBytes = 32 << 10

type grantInput struct {
	PublicKeyPath    string `json:"public_key_path"`
	Epoch            uint64 `json:"epoch"`
	NotBeforeVersion uint64 `json:"not_before_version"`
	NotAfterVersion  uint64 `json:"not_after_version"`
}

func main() {
	log.SetFlags(0)
	rootPrivatePath := flag.String("root-private", "", "offline root private key path")
	grantsPath := flag.String("grants", "", "JSON key grants input path")
	outputPath := flag.String("out", "", "new signed key policy output path")
	policyVersion := flag.Uint64("policy-version", 0, "monotonic key policy version")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}
	if *rootPrivatePath == "" || *grantsPath == "" || *outputPath == "" || *policyVersion == 0 {
		log.Fatal("root-private, grants, out, and a positive policy-version are required")
	}
	rootPrivateKey, err := signingkey.LoadPrivate(*rootPrivatePath)
	if err != nil {
		log.Fatal(err)
	}
	inputs, err := loadGrantInputs(*grantsPath)
	if err != nil {
		log.Fatal(err)
	}
	grants := make([]manifest.KeyGrant, 0, len(inputs))
	for _, input := range inputs {
		publicKey, err := signingkey.LoadPublic(input.PublicKeyPath)
		if err != nil {
			log.Fatal(err)
		}
		grant, err := manifest.NewKeyGrant(publicKey, input.Epoch, input.NotBeforeVersion, input.NotAfterVersion)
		if err != nil {
			log.Fatal(err)
		}
		grants = append(grants, grant)
	}
	policy, err := manifest.SignKeyPolicy(rootPrivateKey, *policyVersion, grants)
	if err != nil {
		log.Fatal(err)
	}
	if err := writePolicy(*outputPath, policy); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stdout, "generated key policy %d for root %s\n", policy.Version, policy.RootKeyID)
}

func loadGrantInputs(path string) ([]grantInput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open grants: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxGrantFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	if len(data) == 0 || len(data) > maxGrantFileBytes {
		return nil, errors.New("grants file size is invalid")
	}
	var inputs []grantInput
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inputs); err != nil {
		return nil, fmt.Errorf("decode grants: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, err
	}
	if len(inputs) == 0 || len(inputs) > 64 {
		return nil, errors.New("grants must contain between 1 and 64 entries")
	}
	return inputs, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("grants file contains multiple JSON values")
}

func writePolicy(path string, policy manifest.KeyPolicy) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create key policy: %w", err)
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(policy); err != nil {
		return fmt.Errorf("encode key policy: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync key policy: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close key policy: %w", err)
	}
	succeeded = true
	return nil
}
