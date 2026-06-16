package store

import (
	"encoding/json"
	"os"

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
	return os.WriteFile(path, append(data, '\n'), 0644)
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
