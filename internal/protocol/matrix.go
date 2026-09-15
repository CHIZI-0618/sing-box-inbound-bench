package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type MatrixConfig struct {
	ProtocolVersion string   `json:"protocol_version"`
	MatrixID        string   `json:"matrix_id"`
	Seed            int64    `json:"seed"`
	OutputDirectory string   `json:"output_directory"`
	Resume          bool     `json:"resume,omitempty"`
	RawControl      *Config  `json:"raw_control,omitempty"`
	Cases           []Config `json:"cases"`
}

func ReadMatrixConfig(path string) (MatrixConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return MatrixConfig{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var matrix MatrixConfig
	if err = decoder.Decode(&matrix); err != nil {
		return MatrixConfig{}, err
	}
	if err = ensureEOF(decoder); err != nil {
		return MatrixConfig{}, err
	}
	return matrix, NormalizeAndValidateMatrix(&matrix)
}

func NormalizeAndValidateMatrix(matrix *MatrixConfig) error {
	if matrix.ProtocolVersion == "" {
		matrix.ProtocolVersion = Version
	}
	if matrix.Seed == 0 {
		matrix.Seed = 1
	}
	var errs []error
	if matrix.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if !runIDPattern.MatchString(matrix.MatrixID) {
		errs = append(errs, errors.New("matrix_id must match the run_id syntax"))
	}
	if matrix.OutputDirectory == "" {
		errs = append(errs, errors.New("output_directory is required"))
	} else if filepath.Clean(matrix.OutputDirectory) == string(filepath.Separator) {
		errs = append(errs, errors.New("output_directory cannot be a filesystem root"))
	}
	if len(matrix.Cases) == 0 {
		errs = append(errs, errors.New("at least one matrix case is required"))
	}
	seen := make(map[string]bool)
	for index := range matrix.Cases {
		matrix.Cases[index].ApplyDefaults()
		if validationErr := matrix.Cases[index].Validate(); validationErr != nil {
			errs = append(errs, fmt.Errorf("case %d: %w", index, validationErr))
		}
		if seen[matrix.Cases[index].RunID] {
			errs = append(errs, fmt.Errorf("duplicate case run_id %q", matrix.Cases[index].RunID))
		}
		seen[matrix.Cases[index].RunID] = true
	}
	if matrix.RawControl != nil {
		matrix.RawControl.ApplyDefaults()
		if validationErr := matrix.RawControl.Validate(); validationErr != nil {
			errs = append(errs, fmt.Errorf("raw_control: %w", validationErr))
		} else if matrix.RawControl.Subject.Kind != SubjectRaw {
			errs = append(errs, errors.New("raw_control subject must be raw"))
		}
	}
	return errors.Join(errs...)
}

type MatrixJob struct {
	ID       string      `json:"id"`
	CaseID   string      `json:"case_id"`
	Subject  SubjectKind `json:"subject"`
	Block    int         `json:"block"`
	Warmup   bool        `json:"warmup"`
	Control  string      `json:"control,omitempty"`
	Result   string      `json:"result"`
	Complete bool        `json:"complete"`
	Valid    bool        `json:"valid"`
	Error    string      `json:"error,omitempty"`
}

type MatrixState struct {
	ProtocolVersion string      `json:"protocol_version"`
	MatrixID        string      `json:"matrix_id"`
	Seed            int64       `json:"seed"`
	Jobs            []MatrixJob `json:"jobs"`
}

func DecodeRepetition(path string) (Repetition, error) {
	file, err := os.Open(path)
	if err != nil {
		return Repetition{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var repetition Repetition
	if err = decoder.Decode(&repetition); err != nil {
		return Repetition{}, err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return Repetition{}, errors.New("result contains trailing JSON")
	}
	if repetition.ProtocolVersion != Version {
		return Repetition{}, errors.New("result protocol version mismatch")
	}
	return repetition, nil
}
