package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONUsesRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.nljson")
	if err := WriteJSON(path, map[string]string{"status": "ok"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("output permissions = %04o, want 0600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != "{\n  \"status\": \"ok\"\n}\n" {
		t.Fatalf("unexpected output: %q", data)
	}
}

func TestWriteJSONReplacesExistingFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.nljson")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, map[string]bool{"new": true}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("replacement permissions = %04o, want 0600", got)
	}
}
