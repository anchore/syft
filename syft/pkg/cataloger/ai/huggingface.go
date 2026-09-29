package ai

import (
	"bytes"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// hfConfig is a minimal projection of Hugging Face config.json fields.
type hfConfig struct {
	Architectures []string `json:"architectures"`
	NameOrPath    string   `json:"_name_or_path"`
}

// looksLikeHF reports whether the config carries any field we use. Other JSON
// (generation_config.json, unrelated app configs) is ignored.
func (c hfConfig) looksLikeHF() bool {
	return len(c.Architectures) > 0 || c.NameOrPath != ""
}

func applyHFConfig(md *pkg.SafeTensorsModelInfo, cfg *hfConfig) {
	if md.Architecture == "" && len(cfg.Architectures) > 0 {
		md.Architecture = cfg.Architectures[0]
	}
}

// readmeFrontmatter holds the subset of YAML frontmatter fields we extract.
type readmeFrontmatter struct {
	Licenses  []string
	BaseModel []string
}

type licenseFrontmatter struct {
	SPDXID string `yaml:"spdx-id"`
}

// extractFrontmatterBlock returns the YAML bytes between the first and second
// "---" delimiter lines of a file
func extractFrontmatterBlock(buf []byte) []byte {
	trimmed := bytes.TrimLeft(buf, "\xef\xbb\xbf \t\r\n")
	first, rest, _ := bytes.Cut(trimmed, []byte("\n"))
	if !isFrontmatterDelimiter(first) {
		return nil
	}
	for off := 0; off < len(rest); {
		line, _, found := bytes.Cut(rest[off:], []byte("\n"))
		if isFrontmatterDelimiter(line) {
			if off == 0 || off > maxFrontmatterSize {
				return nil
			}
			return rest[:off]
		}
		if !found {
			break
		}
		off += len(line) + 1
	}
	return nil
}

// isFrontmatterDelimiter reports whether a line is exactly "---", ignoring
// trailing whitespace and \r.
func isFrontmatterDelimiter(line []byte) bool {
	return bytes.Equal(bytes.TrimRight(line, " \t\r"), []byte("---"))
}

// parseFrontmatter decodes a Hugging Face model card YAML frontmatter block
// and returns the license and base_model fields.
func parseFrontmatter(buf []byte) *readmeFrontmatter {
	block := extractFrontmatterBlock(buf)
	if block == nil {
		return nil
	}

	// both fields may be a scalar or a list, so decode them as nodes
	var raw struct {
		License   yaml.Node `yaml:"license"`
		BaseModel yaml.Node `yaml:"base_model"`
	}
	if err := yaml.Unmarshal(block, &raw); err != nil {
		log.Debugf("failed to parse README frontmatter: %v", err)
		return nil
	}

	return &readmeFrontmatter{
		Licenses:  yamlStrings(raw.License),
		BaseModel: yamlStrings(raw.BaseModel),
	}
}

// yamlStrings returns the non-empty, non-null values of a scalar or a sequence
// of scalars, keeping at most maxFrontmatterValues. Anything else yields nil.
func yamlStrings(n yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		if isYAMLString(&n) {
			return []string{n.Value}
		}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			if len(out) == maxFrontmatterValues {
				break
			}
			if c.Kind == yaml.ScalarNode && isYAMLString(c) {
				out = append(out, c.Value)
			}
		}
		return out
	}
	return nil
}

func isYAMLString(n *yaml.Node) bool {
	return n.Value != "" && n.ShortTag() != "!!null"
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
