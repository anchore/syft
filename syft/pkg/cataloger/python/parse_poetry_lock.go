package python

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// integrity check
var _ generic.Parser = parsePoetryLock

type poetryPackageSource struct {
	URL       string `toml:"url"`
	Type      string `toml:"type"`
	Reference string `toml:"reference"`
}

type poetryPackages struct {
	Packages []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name         string                               `toml:"name"`
	Version      string                               `toml:"version"`
	Category     string                               `toml:"category"`
	Description  string                               `toml:"description"`
	Optional     bool                                 `toml:"optional"`
	Source       poetryPackageSource                  `toml:"source"`
	Dependencies map[string][]poetryPackageDependency `toml:"dependencies"`
	Extras       map[string][]string                  `toml:"extras"`
}

type poetryPackageDependency struct {
	Version  string   `toml:"version"`
	Markers  string   `toml:"markers"`
	Optional bool     `toml:"optional"`
	Extras   []string `toml:"extras"`
}

func (p *poetryPackage) UnmarshalTOML(data any) error {
	d, _ := data.(map[string]any)
	err := p.decodeTomlFields(d)
	if err != nil {
		return err
	}
	return err
}

func (p *poetryPackage) decodeTomlFields(d map[string]interface{}) error {
	newPackage := poetryPackage{}
	structType := reflect.TypeOf(newPackage)
	structValue := reflect.ValueOf(&newPackage).Elem()
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		tag := field.Tag.Get("toml")
		if tag == "" {
			continue
		}

		// Check if the field exists in the map
		value, ok := d[tag]
		if !ok {
			continue
		}

		// Set the field value in the struct
		structField := structValue.FieldByName(field.Name)
		if !structField.IsValid() || !structField.CanSet() {
			continue
		}

		// Convert the value to the field type
		switch structField.Kind() {
		case reflect.String:
			structField.SetString(value.(string))
		case reflect.Int:
			structField.SetInt(int64(value.(int)))
		case reflect.Bool:
			structField.SetBool(value.(bool))
		case reflect.Struct:
			// If the field is a struct, recursively decode it
			mapValue := value.(map[string]interface{})
			decodeStruct(mapValue, structField.Addr().Interface())
		case reflect.Map:
			switch tag {
			case "dependencies":
				value = parseDependencies(value)
				structField.Set(reflect.ValueOf(value))
			case "extras":
				value = parsePoetryExtras(value)
				structField.Set(reflect.ValueOf(value))
			}
		default:
		}
	}
	p.Name = newPackage.Name
	p.Version = newPackage.Version
	p.Category = newPackage.Category
	p.Description = newPackage.Description
	p.Optional = newPackage.Optional
	p.Source = newPackage.Source
	p.Extras = newPackage.Extras
	p.Dependencies = newPackage.Dependencies
	p.Extras = newPackage.Extras
	return nil
}

func parsePoetryExtras(d any) map[string][]string {
	extras := map[string][]string{}
	parsedData := d.(map[string]interface{})
	for key, value := range parsedData {
		extras[key] = convertSliceString(value)
	}
	return extras
}

func convertSliceString(is interface{}) []string {
	// Convert slice of interface{} to slice of string
	iss := is.([]interface{})
	var stringSlice []string
	for _, val := range iss {
		if str, ok := val.(string); ok {
			stringSlice = append(stringSlice, str)
		}
	}
	return stringSlice
}

func parseDependencies(d any) map[string][]poetryPackageDependency {
	dependencies := map[string][]poetryPackageDependency{}
	// we know we have dependencies here so let's convert to a map[string]interface{}
	parsedData := d.(map[string]interface{})
	for key, value := range parsedData {
		dependencies[key] = make([]poetryPackageDependency, 0)
		t := reflect.TypeOf(value)
		switch t.Kind() {
		case reflect.String:
			dependencies[key] = append(dependencies[key], poetryPackageDependency{Version: value.(string)})
		case reflect.Slice:
			complexDeps := value.([]interface{})
			for _, complex := range complexDeps {
				convertedComplex := complex.(map[string]interface{})
				// TODO: we need to assert these map values or we will panic
				newDep := poetryPackageDependency{
					Version: convertedComplex["version"].(string),
					Markers: convertedComplex["markers"].(string),
				}
				dependencies[key] = append(dependencies[key], newDep)
			}
		}
	}
	return dependencies
}

func decodeStruct(data map[string]interface{}, v interface{}) {
	structType := reflect.TypeOf(v).Elem()
	structValue := reflect.ValueOf(v).Elem()

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		tag := field.Tag.Get("toml")
		if tag == "" {
			continue
		}

		value, ok := data[tag]
		if !ok {
			continue
		}

		fieldValue := structValue.Field(i)
		if !fieldValue.IsValid() || !fieldValue.CanSet() {
			continue
		}

		switch fieldValue.Kind() {
		case reflect.String:
			fieldValue.SetString(value.(string))
		case reflect.Int:
			fieldValue.SetInt(int64(value.(int)))
		default:
			fmt.Println("Unsupported type")
		}
	}
}

// parsePoetryLock is a parser function for poetry.lock contents, returning all python packages discovered.
func parsePoetryLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, err := poetryLockPackages(reader)
	if err != nil {
		return nil, nil, err
	}

	// since we would never expect to create relationships for packages across multiple poetry.lock files
	// we should do this on a file parser level (each poetry.lock) instead of a cataloger level (across all
	// poetry.lock files)
	return pkgs, dependency.Resolve(poetryLockDependencySpecifier, pkgs), nil
}

func poetryLockPackages(reader file.LocationReadCloser) ([]pkg.Package, error) {
	metadata := poetryPackages{}
	_, err := toml.NewDecoder(reader).Decode(&metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to read poetry lock package: %w", err)
	}

	var pkgs []pkg.Package
	for _, p := range metadata.Packages {
		pkgs = append(
			pkgs,
			newPackageForIndexWithMetadata(
				p.Name,
				p.Version,
				newPythonPoetryLockEntry(p),
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}
	return pkgs, nil
}

func newPythonPoetryLockEntry(p poetryPackage) pkg.PythonPoetryLockEntry {
	return pkg.PythonPoetryLockEntry{
		Index:        extractIndex(p),
		Dependencies: extractPoetryDependencies(p),
		Extras:       extractPoetryExtras(p),
	}
}

func extractIndex(p poetryPackage) string {
	if p.Source.URL != "" {
		return p.Source.URL
	}
	// https://python-poetry.org/docs/repositories/
	return "https://pypi.org/simple"
}

func extractPoetryDependencies(p poetryPackage) []pkg.PythonPoetryLockDependencyEntry {
	var deps []pkg.PythonPoetryLockDependencyEntry
	for name, dependencies := range p.Dependencies {
		for _, d := range dependencies {
			deps = append(deps, pkg.PythonPoetryLockDependencyEntry{
				Name:    name,
				Version: d.Version,
				Extras:  d.Extras,
				Markers: d.Markers,
			})
		}
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})
	return deps
}

func extractPoetryExtras(p poetryPackage) []pkg.PythonPoetryLockExtraEntry {
	var extras []pkg.PythonPoetryLockExtraEntry
	for name, deps := range p.Extras {
		extras = append(extras, pkg.PythonPoetryLockExtraEntry{
			Name:         name,
			Dependencies: deps,
		})
	}
	sort.Slice(extras, func(i, j int) bool {
		return extras[i].Name < extras[j].Name
	})
	return extras
}
