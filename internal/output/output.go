package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"gopkg.in/yaml.v3"
)

type Format string

const (
	JSON   Format = "json"
	YAML   Format = "yaml"
	Signal Format = "signal"
)

func Validate(format string) error {
	switch Format(format) {
	case JSON, YAML, Signal:
		return nil
	default:
		return fmt.Errorf("unsupported output format %q; use json, yaml, or signal", format)
	}
}

func Results(w io.Writer, format Format, results []model.Result) error {
	for i, result := range results {
		switch format {
		case JSON:
			if err := json.NewEncoder(w).Encode(result); err != nil {
				return err
			}
		case YAML:
			if i > 0 {
				if _, err := io.WriteString(w, "---\n"); err != nil {
					return err
				}
			}
			if err := yaml.NewEncoder(w).Encode(result); err != nil {
				return err
			}
		case Signal:
			envelope := struct {
				Signal string       `json:"signal"`
				Data   model.Result `json:"data"`
			}{Signal: model.SignalType, Data: result}
			if err := json.NewEncoder(w).Encode(envelope); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported output format %q", format)
		}
	}
	return nil
}

func Value(w io.Writer, format Format, value any) error {
	switch format {
	case JSON, Signal:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	case YAML:
		return yaml.NewEncoder(w).Encode(value)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}
