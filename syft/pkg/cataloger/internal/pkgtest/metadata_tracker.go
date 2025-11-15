// Package pkgtest provides test helpers for cataloger and parser testing,
// including automatic observation tracking for capability documentation.
package pkgtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/anchore/syft/internal/capabilities/pkgtestobservation"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

var (
	globalTracker     *MetadataTracker
	globalTrackerOnce sync.Once

	// commonPackageIntegrityFields are common field names used to store integrity hashes in package metadata.
	// TODO: this is a best-effort list and may need to be expanded as new package types are added. Don't depend on this list to catch everything - it's only for test validation.
	commonPackageIntegrityFields = []string{
		"Integrity", "Checksum", "H1Digest",
		"OutputHash", "PkgHash", "ContentHash",
		"PkgHashExt", "Hash", "IntegrityHash",
	}
)

// MetadataTracker collects metadata type and package type usage during test execution
type MetadataTracker struct {
	mu                    sync.Mutex
	parserData            map[string]map[string]map[string]bool // package -> parser -> metadata types (set)
	catalogerData         map[string]map[string]bool            // cataloger -> metadata types (set)
	parserPackageTypes    map[string]map[string]map[string]bool // package -> parser -> package types (set)
	catalogerPackageTypes map[string]map[string]bool            // cataloger -> package types (set)

	// unified observations for the current test package
	observations *pkgtestobservation.Test
}

// getTracker returns the singleton metadata tracker
func getTracker() *MetadataTracker {
	globalTrackerOnce.Do(func() {
		globalTracker = &MetadataTracker{
			parserData:            make(map[string]map[string]map[string]bool),
			catalogerData:         make(map[string]map[string]bool),
			parserPackageTypes:    make(map[string]map[string]map[string]bool),
			catalogerPackageTypes: make(map[string]map[string]bool),
		}
	})
	return globalTracker
}

// RecordParser records a metadata type usage for a parser function
func (t *MetadataTracker) RecordParser(packageName, parserFunction, metadataType string) {
	if packageName == "" || parserFunction == "" || metadataType == "" {
		return
	}

	// filter out non-metadata types
	if metadataType == "pkg.Package" || metadataType == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.parserData[packageName] == nil {
		t.parserData[packageName] = make(map[string]map[string]bool)
	}

	if t.parserData[packageName][parserFunction] == nil {
		t.parserData[packageName][parserFunction] = make(map[string]bool)
	}

	t.parserData[packageName][parserFunction][metadataType] = true
}

// RecordCataloger records a metadata type usage for a cataloger
func (t *MetadataTracker) RecordCataloger(catalogerName, metadataType string) {
	if catalogerName == "" || metadataType == "" {
		return
	}

	// filter out non-metadata types
	if metadataType == "pkg.Package" || metadataType == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.catalogerData[catalogerName] == nil {
		t.catalogerData[catalogerName] = make(map[string]bool)
	}

	t.catalogerData[catalogerName][metadataType] = true
}

// RecordParserPackageType records a package type usage for a parser function
func (t *MetadataTracker) RecordParserPackageType(packageName, parserFunction, pkgType string) {
	if packageName == "" || parserFunction == "" || pkgType == "" {
		return
	}

	// filter out unknown types
	if pkgType == pkg.UnknownPkg.String() || pkgType == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.parserPackageTypes[packageName] == nil {
		t.parserPackageTypes[packageName] = make(map[string]map[string]bool)
	}

	if t.parserPackageTypes[packageName][parserFunction] == nil {
		t.parserPackageTypes[packageName][parserFunction] = make(map[string]bool)
	}

	t.parserPackageTypes[packageName][parserFunction][pkgType] = true
}

// RecordCatalogerPackageType records a package type usage for a cataloger
func (t *MetadataTracker) RecordCatalogerPackageType(catalogerName, pkgType string) {
	if catalogerName == "" || pkgType == "" {
		return
	}

	// filter out unknown types
	if pkgType == pkg.UnknownPkg.String() || pkgType == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.catalogerPackageTypes[catalogerName] == nil {
		t.catalogerPackageTypes[catalogerName] = make(map[string]bool)
	}

	t.catalogerPackageTypes[catalogerName][pkgType] = true
}

// RecordParserPackageMetadata extracts and records metadata type and package type from a package for a parser
func (t *MetadataTracker) RecordParserPackageMetadata(packageName, parserFunction string, p pkg.Package) {
	if p.Metadata != nil {
		metadataType := getMetadataTypeName(p.Metadata)
		if metadataType != "" {
			t.RecordParser(packageName, parserFunction, metadataType)
		}
	}

	// record package type
	t.RecordParserPackageType(packageName, parserFunction, string(p.Type))
}

// RecordCatalogerPackageMetadata extracts and records metadata type and package type from a package for a cataloger
func (t *MetadataTracker) RecordCatalogerPackageMetadata(catalogerName string, p pkg.Package) {
	if p.Metadata != nil {
		metadataType := getMetadataTypeName(p.Metadata)
		if metadataType != "" {
			t.RecordCataloger(catalogerName, metadataType)
		}
	}

	// record package type
	t.RecordCatalogerPackageType(catalogerName, string(p.Type))
}

// aggregateObservations aggregates package and relationship observations into metadata types, package types, and observations.
// this is used by both parser and cataloger observation recording.
func aggregateObservations(
	metadataTypes *[]string,
	packageTypes *[]string,
	obs *pkgtestobservation.Observations,
	pkgs []pkg.Package,
	relationships []artifact.Relationship,
) {
	// aggregate observations from packages
	for _, p := range pkgs {
		// metadata types
		if p.Metadata != nil {
			metadataType := getMetadataTypeName(p.Metadata)
			if metadataType != "" && !contains(*metadataTypes, metadataType) {
				*metadataTypes = append(*metadataTypes, metadataType)
			}
		}

		// package types
		pkgType := string(p.Type)
		if pkgType != "" && pkgType != pkg.UnknownPkg.String() && !contains(*packageTypes, pkgType) {
			*packageTypes = append(*packageTypes, pkgType)
		}

		// license observation
		if !p.Licenses.Empty() {
			obs.License = true
		}

		// file listing observation
		if fileOwner, ok := p.Metadata.(pkg.FileOwner); ok {
			files := fileOwner.OwnedFiles()
			if len(files) > 0 {
				obs.FileListing.Found = true
				obs.FileListing.Count += len(files)
			}
		}

		// file digests observation
		if hasFileDigests(p.Metadata) {
			obs.FileDigests.Found = true
			obs.FileDigests.Count++
		}

		// integrity hash observation
		if hasIntegrityHash(p.Metadata) {
			obs.IntegrityHash.Found = true
			obs.IntegrityHash.Count++
		}
	}

	// relationship observations
	depCount := countDependencyRelationships(relationships)
	if depCount > 0 {
		obs.Relationships.Found = true
		obs.Relationships.Count = depCount
	}

	// sort arrays for consistency
	sort.Strings(*metadataTypes)
	sort.Strings(*packageTypes)
}

// ensureObservationsInitialized ensures t.observations is initialized and package name is set.
// must be called with t.mu locked.
func (t *MetadataTracker) ensureObservationsInitialized(packageName string) {
	if t.observations == nil {
		t.observations = &pkgtestobservation.Test{
			Package:    packageName,
			Catalogers: make(map[string]*pkgtestobservation.Cataloger),
			Parsers:    make(map[string]*pkgtestobservation.Parser),
		}
		return
	}

	// update package name if not set (for the first test) or if it matches (for subsequent tests in same package)
	if t.observations.Package == "" || t.observations.Package == packageName {
		t.observations.Package = packageName
	}
}

// getOrCreateParser gets an existing parser observation or creates a new one.
// must be called with t.mu locked.
func (t *MetadataTracker) getOrCreateParser(parserFunction string) *pkgtestobservation.Parser {
	if t.observations.Parsers[parserFunction] == nil {
		t.observations.Parsers[parserFunction] = &pkgtestobservation.Parser{
			MetadataTypes: []string{},
			PackageTypes:  []string{},
			Observations:  pkgtestobservation.Observations{},
		}
	}
	return t.observations.Parsers[parserFunction]
}

// getOrCreateCataloger gets an existing cataloger observation or creates a new one.
// must be called with t.mu locked.
func (t *MetadataTracker) getOrCreateCataloger(catalogerName string) *pkgtestobservation.Cataloger {
	if t.observations.Catalogers[catalogerName] == nil {
		t.observations.Catalogers[catalogerName] = &pkgtestobservation.Cataloger{
			MetadataTypes: []string{},
			PackageTypes:  []string{},
			Observations:  pkgtestobservation.Observations{},
		}
	}
	return t.observations.Catalogers[catalogerName]
}

// RecordParserObservations records comprehensive observations for a parser.
func (t *MetadataTracker) RecordParserObservations(
	packageName, parserFunction string,
	pkgs []pkg.Package,
	relationships []artifact.Relationship,
) {
	if packageName == "" || parserFunction == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.ensureObservationsInitialized(packageName)
	parser := t.getOrCreateParser(parserFunction)
	aggregateObservations(&parser.MetadataTypes, &parser.PackageTypes, &parser.Observations, pkgs, relationships)
}

// RecordCatalogerObservations records comprehensive observations for a cataloger.
func (t *MetadataTracker) RecordCatalogerObservations(
	packageName, catalogerName string,
	pkgs []pkg.Package,
	relationships []artifact.Relationship,
) {
	if packageName == "" || catalogerName == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.ensureObservationsInitialized(packageName)
	cataloger := t.getOrCreateCataloger(catalogerName)
	aggregateObservations(&cataloger.MetadataTypes, &cataloger.PackageTypes, &cataloger.Observations, pkgs, relationships)
}

// ===== Metadata Type and Capability Detection =====
// These functions use reflection to inspect package metadata and detect capabilities.
// They are best-effort and may not catch all cases.

// getMetadataTypeName returns the fully qualified type name of metadata (e.g., "pkg.ApkDBEntry").
// extracts just the last package path segment to keep names concise.
func getMetadataTypeName(metadata interface{}) string {
	if metadata == nil {
		return ""
	}

	t := reflect.TypeOf(metadata)
	if t == nil {
		return ""
	}

	// handle pointers
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// return pkg path + type name (e.g., "pkg.ApkDBEntry")
	if t.PkgPath() != "" {
		// extract just "pkg" from "github.com/anchore/syft/syft/pkg"
		pkgPath := lastPathSegment(t.PkgPath())
		return pkgPath + "." + t.Name()
	}

	return t.Name()
}

// lastPathSegment extracts the last segment from a package path.
// for example: "github.com/anchore/syft/syft/pkg" -> "pkg"
func lastPathSegment(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// hasIntegrityHash checks if metadata contains an integrity hash field.
// note: this uses a best-effort approach checking common field names.
// DO NOT depend on these values in auto-generated capabilities definitions - use for test validation only.
func hasIntegrityHash(metadata interface{}) bool {
	v := dereferenceToStruct(metadata)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return false
	}

	for _, fieldName := range commonPackageIntegrityFields {
		if hasPopulatedStringField(v, fieldName) {
			return true
		}
	}
	return false
}

// hasFileDigests checks if metadata contains file records with digests.
// note: uses a best-effort approach for detection.
// DO NOT depend on these values in auto-generated capabilities definitions - use for test validation only.
func hasFileDigests(metadata interface{}) bool {
	v := dereferenceToStruct(metadata)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return false
	}

	filesField := v.FieldByName("Files")
	if !filesField.IsValid() || filesField.Kind() != reflect.Slice {
		return false
	}

	// check if any file record has a Digest field populated
	for i := 0; i < filesField.Len(); i++ {
		if hasPopulatedDigest(filesField.Index(i)) {
			return true
		}
	}
	return false
}

// dereferenceToStruct handles pointer dereferencing and returns the underlying value.
// returns an invalid value if the input is nil or not convertible to a struct.
func dereferenceToStruct(v interface{}) reflect.Value {
	if v == nil {
		return reflect.Value{}
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return reflect.Value{}
		}
		val = val.Elem()
	}
	return val
}

// hasPopulatedStringField checks if a struct has a non-empty string field with the given name.
func hasPopulatedStringField(v reflect.Value, fieldName string) bool {
	field := v.FieldByName(fieldName)
	return field.IsValid() && field.Kind() == reflect.String && field.String() != ""
}

// hasPopulatedDigest checks if a file record has a populated Digest field.
func hasPopulatedDigest(fileRecord reflect.Value) bool {
	fileRecord = dereferenceToStruct(fileRecord.Interface())
	if !fileRecord.IsValid() || fileRecord.Kind() != reflect.Struct {
		return false
	}

	digestField := fileRecord.FieldByName("Digest")
	if !digestField.IsValid() {
		return false
	}

	// check if digest is a pointer and not nil, or a non-zero value
	switch digestField.Kind() {
	case reflect.Ptr:
		return !digestField.IsNil()
	case reflect.String:
		return digestField.String() != ""
	case reflect.Struct:
		return !digestField.IsZero()
	}
	return false
}

// ===== Utility Functions =====

// countDependencyRelationships counts the number of dependency relationships.
func countDependencyRelationships(relationships []artifact.Relationship) int {
	count := 0
	for _, rel := range relationships {
		if rel.Type == artifact.DependencyOfRelationship {
			count++
		}
	}
	return count
}

// contains checks if a string slice contains a specific string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ===== Result Writing =====

// WriteResults writes the collected observation data to test-fixtures/test-observations.json.
func (t *MetadataTracker) WriteResults() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.observations == nil {
		// no data to write
		return nil
	}

	// create output directory
	outDir := "test-fixtures"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// write unified test-observations.json
	t.observations.UpdatedAt = time.Now().UTC()

	filename := filepath.Join(outDir, "test-observations.json")
	return writeJSONFile(filename, t.observations)
}

// writeJSONFile writes data as pretty-printed JSON to the specified path.
func writeJSONFile(path string, data interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// WriteResultsIfEnabled writes results if tracking is enabled.
// this is typically called via t.Cleanup() in tests.
func WriteResultsIfEnabled() error {
	tracker := getTracker()
	return tracker.WriteResults()
}
