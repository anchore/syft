package perl

import (
	"encoding/json"
	"io"
	"path"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// cpanMeta models the parts of a CPAN Meta Spec document syft uses. One shape covers all three:
// META.json (spec 2), MYMETA.json (the configure-time rendering of META.json), and META.yml (spec 1.4).
type cpanMeta struct {
	Name     string                   `json:"name" yaml:"name"`
	Version  scalar                   `json:"version" yaml:"version"`
	Abstract string                   `json:"abstract" yaml:"abstract"`
	License  stringList               `json:"license" yaml:"license"`
	Provides map[string]providesEntry `json:"provides" yaml:"provides"`

	// SPDX is preferred over License when present: a single SPDX expression the author wrote, rather than
	// a CPAN::Meta license token that has to be translated
	SPDX string `json:"x_spdx_expression" yaml:"x_spdx_expression"`

	// Prereqs is the spec 2 shape: phase -> relation -> module -> version
	Prereqs map[string]map[string]map[string]scalar `json:"prereqs" yaml:"prereqs"`

	// Requires and BuildRequires are the spec 1.4 shape, which has no phase nesting. develop and test
	// have no 1.4 equivalent, which costs nothing because they are excluded anyway.
	Requires      map[string]scalar `json:"requires" yaml:"requires"`
	BuildRequires map[string]scalar `json:"build_requires" yaml:"build_requires"`
}

type providesEntry struct {
	Version scalar `json:"version" yaml:"version"`
}

// scalar is a value that CPAN metadata writes as either a quoted string or a bare number. Old
// distributions ship `"version": 1.23` where the spec calls for a string, and a strict string field
// there would fail the whole document rather than one field.
type scalar string

func (s *scalar) UnmarshalJSON(b []byte) error {
	raw := string(b)
	if raw == "null" {
		return nil
	}
	if len(raw) >= 2 && raw[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		*s = scalar(str)
		return nil
	}
	*s = scalar(raw)
	return nil
}

// UnmarshalYAML exists for the same reason UnmarshalJSON does, and separately from it: the YAML decoder
// does not honor json.Unmarshaler, so without this a `version: 1.23` in a META.yml would fail the whole
// document. A YAML scalar node's value is already the text as written, so there is nothing to convert.
func (s *scalar) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == "!!null" {
		return nil
	}
	*s = scalar(value.Value)
	return nil
}

// stringList is a value that is a list of strings in CPAN Meta Spec 2 but a bare string in spec 1.4.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	var many []string
	if err := json.Unmarshal(b, &many); err == nil {
		*s = many
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = stringList{one}
	}
	return nil
}

func (s *stringList) UnmarshalYAML(value *yaml.Node) error {
	var many []string
	if err := value.Decode(&many); err == nil {
		*s = many
		return nil
	}
	var one string
	if err := value.Decode(&one); err == nil {
		*s = stringList{one}
	}
	return nil
}

// readMyMeta reads the MYMETA.json that cpanm, cpm, and carton write beside install.json. A missing or
// unreadable MYMETA is not an error: the distribution is still real, it just has fewer facts attached.
func readMyMeta(resolver file.Resolver, installJSONLocation file.Location) (*file.Location, *cpanMeta) {
	if resolver == nil {
		return nil, nil
	}

	p := path.Join(path.Dir(installJSONLocation.Path()), "MYMETA.json")

	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return nil, nil
	}

	m, err := decodeMeta(resolver, locations[0])
	if err != nil {
		log.WithFields("path", p, "error", err).Debug("unable to parse CPAN MYMETA.json")
		return nil, nil
	}

	return &locations[0], m
}

func decodeMeta(resolver file.Resolver, location file.Location) (*cpanMeta, error) {
	return decode(resolver, location, func(r io.Reader, m *cpanMeta) error {
		return json.NewDecoder(r).Decode(m)
	})
}

// decodeMetaYAML reads a spec 1.4 META.yml. CPAN META.yml files are rejected by strict YAML parsers often
// enough to matter: pre-6.46 ExtUtils::MakeMaker writes values with no quoting or escaping at all, so a
// multi-line ABSTRACT, a value that opens a quote it never closes, and a value starting with >= (which
// YAML reads as a folded block scalar) all get emitted verbatim. Measured over 454 releases from 2004 to
// 2009, five fail. That is a routine failure, not a defensive one, and the caller degrades on it.
func decodeMetaYAML(resolver file.Resolver, location file.Location) (*cpanMeta, error) {
	return decode(resolver, location, func(r io.Reader, m *cpanMeta) error {
		return yaml.NewDecoder(r).Decode(m)
	})
}

func decode(resolver file.Resolver, location file.Location, into func(io.Reader, *cpanMeta) error) (*cpanMeta, error) {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(reader, location.Path())

	var m cpanMeta
	if err := into(reader, &m); err != nil {
		return nil, err
	}

	return &m, nil
}

// prereqModules returns the module names this distribution requires at runtime and build time.
// develop and test phases are excluded: they describe how the distribution was authored, not what a
// deployed copy of it needs. A spec 1.4 document has no phases at all, so its flat requires and
// build_requires maps feed the same two buckets.
func (m *cpanMeta) prereqModules() []string {
	var modules []string
	for _, phase := range []string{"runtime", "build"} {
		for module := range m.Prereqs[phase]["requires"] {
			modules = append(modules, module)
		}
	}
	for _, flat := range []map[string]scalar{m.Requires, m.BuildRequires} {
		for module := range flat {
			modules = append(modules, module)
		}
	}
	return modules
}

// licenseExpressions returns the license values to record on the package. x_spdx_expression wins when
// present: it is a single SPDX expression, which syft's license parsing understands directly, rather
// than a CPAN license shortname such as perl_5 or artistic_2.
func (m *cpanMeta) licenseExpressions() []string {
	if m.SPDX != "" {
		return []string{m.SPDX}
	}
	return m.License
}
