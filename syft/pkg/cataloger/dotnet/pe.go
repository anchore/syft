package dotnet

import (
	"bytes"
	"encoding/json"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pe"
)

// logicalPE represents a PE file within the context of a .NET project (considering the deps.json file).
type logicalPE struct {
	pe.File

	// TargetPath is the path is the deps.json target entry. This is not present in the PE file
	// but instead is used in downstream processing to track associations between the PE file and the deps.json file.
	TargetPath string

	EmbeddedDepsJSON string
}

func readLogicalPE(reader file.LocationReadCloser) (*logicalPE, error) {
	peFile, err := pe.Read(reader)
	if err != nil {
		return nil, err
	}

	if peFile == nil {
		return nil, nil
	}

	return &logicalPE{
		File: *peFile,
	}, nil
}

func extractEmbeddedDepsJSONFromBytes(data []byte) string {
	// search marker deps.json
	marker := []byte(`"runtimeTarget"`)
	idx := bytes.Index(data, marker)
	if idx == -1 {
		return ""
	}

	searchStart := idx - 10240
	if searchStart < 0 {
		searchStart = 0
	}

	start := -1
	for i := idx - 1; i >= searchStart; i-- {
		if data[i] == '{' {
			start = i
			break
		}
	}
	if start == -1 {
		return ""
	}

	dec := json.NewDecoder(bytes.NewReader(data[start:]))
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		return ""
	}

	end := start + int(dec.InputOffset())
	return string(data[start:end])
}
