package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

const maxCatalogBytes = 1 << 20

func LoadFile(path string) (manifest.Catalog, error) {
	// #nosec G304 -- the catalog path is trusted process configuration, not request data.
	file, err := os.Open(path)
	if err != nil {
		return manifest.Catalog{}, fmt.Errorf("open catalog: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxCatalogBytes+1))
	if err != nil {
		return manifest.Catalog{}, fmt.Errorf("read catalog: %w", err)
	}
	if len(data) > maxCatalogBytes {
		return manifest.Catalog{}, errors.New("catalog exceeds 1 MiB")
	}

	var result manifest.Catalog
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return manifest.Catalog{}, fmt.Errorf("decode catalog: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return manifest.Catalog{}, err
	}
	return result, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing catalog data: %w", err)
	}
	return errors.New("catalog contains multiple JSON values")
}
