package internal

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type SnippetMetadata struct {
	Name          string `yaml:"name"`
	Offset        int    `yaml:"offset"`
	Length        int    `yaml:"length"`
	SnippetSha256 string `yaml:"snippetSha256"`
	FileSha256    string `yaml:"fileSha256"`
}

func ReadSnippetMetadata(path string) (*SnippetMetadata, error) {
	if path == "" {
		return nil, nil
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fields := strings.Split(string(contents), "\n### byte snippet to follow ###\n")
	if len(fields) != 2 {
		return nil, fmt.Errorf("this is not a snippet")
	}

	var metadata SnippetMetadata
	if err := yaml.Unmarshal([]byte(fields[0]), &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}
