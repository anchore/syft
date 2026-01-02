package options

import (
	"fmt"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/source"
)

type SBOMConfig struct {
	Authors []string       `yaml:"authors" json:"authors" mapstructure:"authors"` // CLI input
	authors []source.Actor // parsed actors
}

var _ clio.PostLoader = (*SBOMConfig)(nil)

func DefaultSBOMConfig() SBOMConfig {
	return SBOMConfig{}
}

// PostLoad parses the semicolon-separated key=value format for authors
// Example: --sbom-author "type=person;name=John Doe;email=john@example.com"
func (cfg *SBOMConfig) PostLoad() error {
	if len(cfg.Authors) == 0 {
		return nil
	}

	actors := make([]source.Actor, 0, len(cfg.Authors))
	for _, authorStr := range cfg.Authors {
		actor, err := parseActor(authorStr)
		if err != nil {
			return fmt.Errorf("invalid author format: %w", err)
		}
		actors = append(actors, actor)
	}

	cfg.authors = actors
	return nil
}

// parseActor parses ampersand-separated key=value pairs into an Actor
// Format: "type=person&name=John Doe&email=john@example.com"
func parseActor(input string) (source.Actor, error) {
	actor := source.Actor{}

	// Split by ampersand and parse each key=value pair
	for _, pair := range strings.Split(input, "&") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "type":
			actor.Type = strings.ToLower(value)
		case "name":
			actor.Name = value
		case "email":
			actor.Email = value
		}
	}

	if actor.Type == "" || actor.Name == "" {
		return actor, fmt.Errorf("type and name are required")
	}

	// Validate type is one of the allowed values
	switch actor.Type {
	case "person", "organization", "tool":
		// valid types
	default:
		return actor, fmt.Errorf("type must be one of: person, organization, tool (got: %q)", actor.Type)
	}

	return actor, nil
}

// GetAuthors returns the parsed actors
func (cfg *SBOMConfig) GetAuthors() []source.Actor {
	return cfg.authors
}
