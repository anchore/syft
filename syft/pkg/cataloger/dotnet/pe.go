package dotnet

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pe"
)

// logicalPE represents a PE file within the context of a .NET project (considering the deps.json file).
type logicalPE struct {
	pe.File

	// TargetPath is the path is the deps.json target entry. This is not present in the PE file
	// but instead is used in downstream processing to track associations between the PE file and the deps.json file.
	TargetPath string
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
