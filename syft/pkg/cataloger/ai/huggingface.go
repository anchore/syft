package ai

import (
	"bytes"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// hfConfig is a minimal projection of Hugging Face config.json fields.
type hfConfig struct {
	Architectures []string `json:"architectures"`
	NameOrPath    string   `json:"_name_or_path"`
}

func applyHFConfig(md *pkg.SafeTensorsModelInfo, cfg *hfConfig) {
	if md.Architecture == "" && len(cfg.Architectures) > 0 {
		md.Architecture = cfg.Architectures[0]
	}
}

// readmeFrontmatter holds the subset of YAML frontmatter fields we extract.
type readmeFrontmatter struct {
	License   string   `yaml:"license"`
	BaseModel []string `yaml:"base_model"`
}

type licenseFrontmatter struct {
	SPDXID string `yaml:"spdx-id"`
}

// extractFrontmatterBlock returns the YAML bytes between the first and second
// "---" delimiters of a file
func extractFrontmatterBlock(buf []byte) []byte {
	trimmed := bytes.TrimLeft(buf, "\xef\xbb\xbf \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("---")) {
		return nil
	}
	rest := trimmed[3:]
	if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[i+1:]
	}
	block, _, found := bytes.Cut(rest, []byte("\n---"))
	if !found {
		return nil
	}
	return block
}

// parseFrontmatter decodes a Hugging Face model card YAML frontmatter block
// and returns the license and base_model fields.
func parseFrontmatter(buf []byte) *readmeFrontmatter {
	block := extractFrontmatterBlock(buf)
	if block == nil {
		return nil
	}

	var raw struct {
		License   string    `yaml:"license"`
		BaseModel yaml.Node `yaml:"base_model"`
	}
	if err := yaml.Unmarshal(block, &raw); err != nil {
		log.Debugf("failed to parse README frontmatter: %v", err)
		return nil
	}

	fm := readmeFrontmatter{License: raw.License}
	switch raw.BaseModel.Kind {
	case yaml.ScalarNode:
		if raw.BaseModel.Value != "" {
			fm.BaseModel = []string{raw.BaseModel.Value}
		}
	case yaml.SequenceNode:
		_ = raw.BaseModel.Decode(&fm.BaseModel)
	}
	return &fm
}

// parseLicenseFrontmatter returns the producer-declared SPDX identifier
func parseLicenseFrontmatter(buf []byte) string {
	block := extractFrontmatterBlock(buf)
	if block == nil {
		return ""
	}
	var fm licenseFrontmatter
	if err := yaml.Unmarshal(block, &fm); err != nil {
		log.Debugf("failed to parse license frontmatter: %v", err)
		return ""
	}
	return fm.SPDXID
}
