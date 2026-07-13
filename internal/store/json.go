package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Zetascrub/net-link/internal/model"
)

func WriteRun(path string, run model.Run) error {
	return WriteJSON(path, run)
}

func WriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".net-link-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		temp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()

	if err = temp.Chmod(0600); err != nil {
		return err
	}
	if _, err = temp.Write(data); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace evidence file: %w", err)
	}
	return nil
}

func ReadRun(path string) (model.Run, error) {
	var run model.Run
	data, err := os.ReadFile(path)
	if err != nil {
		return run, err
	}
	err = json.Unmarshal(data, &run)
	return run, err
}
