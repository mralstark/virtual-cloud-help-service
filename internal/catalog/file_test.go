package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile(t *testing.T) {
	path := writeCatalog(t, `{"version":1,"nodes":[]}`)
	catalog, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if catalog.Version != 1 {
		t.Fatalf("Version = %d, want 1", catalog.Version)
	}
}

func TestLoadFileRejectsUnknownAndTrailingData(t *testing.T) {
	tests := []string{
		`{"version":1,"nodes":[],"secret":"must-not-be-ignored"}`,
		`{"version":1,"nodes":[]} {"version":2,"nodes":[]}`,
	}
	for _, contents := range tests {
		path := writeCatalog(t, contents)
		if _, err := LoadFile(path); err == nil {
			t.Fatalf("LoadFile() accepted %q", contents)
		}
	}
}

func writeCatalog(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
