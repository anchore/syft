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

const (
	unknownPackageType = "UnknownPackage"
)

var (
	globalTracker     *MetadataTracker
	globalTrackerOnce sync.Once
)

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
	if pkgType == unknownPackageType || pkgType == "" {
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
	if pkgType == unknownPackageType || pkgType == "" {
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

// observationHolder provides a common interface for parser and cataloger observations
type observationHolder interface {
	GetMetadataTypes() *[]string
	GetPackageTypes() *[]string
	GetObservations() *pkgtestobservation.Observations
}

// parserObservationHolder wraps a parser observation
type parserObservationHolder struct{ *pkgtestobservation.Parser }

func (p parserObservationHolder) GetMetadataTypes() *[]string {
	return &p.MetadataTypes
}
func (p parserObservationHolder) GetPackageTypes() *[]string {
	return &p.PackageTypes
}
func (p parserObservationHolder) GetObservations() *pkgtestobservation.Observations {
	return &p.Observations
}

// catalogerObservationHolder wraps a cataloger observation
type catalogerObservationHolder struct{ *pkgtestobservation.Cataloger }

func (c catalogerObservationHolder) GetMetadataTypes() *[]string {
	return &c.MetadataTypes
}
func (c catalogerObservationHolder) GetPackageTypes() *[]string {
	return &c.PackageTypes
}
func (c catalogerObservationHolder) GetObservations() *pkgtestobservation.Observations {
	return &c.Observations
}

// aggregateObservations aggregates package and relationship observations into the holder
func aggregateObservations(holder observationHolder, pkgs []pkg.Package, relationships []artifact.Relationship) {
	metadataTypes := holder.GetMetadataTypes()
	packageTypes := holder.GetPackageTypes()
	obs := holder.GetObservations()

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
		if pkgType != "" && pkgType != unknownPackageType && !contains(*packageTypes, pkgType) {
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
	}

	// update package name if not set (for the first test) or if it matches (for subsequent tests in same package)
	if t.observations.Package == "" || t.observations.Package == packageName {
		t.observations.Package = packageName
	}
}

// RecordParserObservations records comprehensive observations for a parser
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

	// get or create parser observation
	if t.observations.Parsers[parserFunction] == nil {
		t.observations.Parsers[parserFunction] = &pkgtestobservation.Parser{
			MetadataTypes: []string{},
			PackageTypes:  []string{},
			Observations:  pkgtestobservation.Observations{},
		}
	}

	aggregateObservations(parserObservationHolder{t.observations.Parsers[parserFunction]}, pkgs, relationships)
}

// RecordCatalogerObservations records comprehensive observations for a cataloger
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

	// get or create cataloger observation
	if t.observations.Catalogers[catalogerName] == nil {
		t.observations.Catalogers[catalogerName] = &pkgtestobservation.Cataloger{
			MetadataTypes: []string{},
			PackageTypes:  []string{},
			Observations:  pkgtestobservation.Observations{},
		}
	}

	aggregateObservations(catalogerObservationHolder{t.observations.Catalogers[catalogerName]}, pkgs, relationships)
}

// getMetadataTypeName returns the fully qualified type name of metadata
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
		pkgPath := t.PkgPath()
		if idx := len(pkgPath) - 1; idx >= 0 {
			// find last segment
			for i := len(pkgPath) - 1; i >= 0; i-- {
				if pkgPath[i] == '/' {
					pkgPath = pkgPath[i+1:]
					break
				}
			}
		}
		return pkgPath + "." + t.Name()
	}

	return t.Name()
}

// hasIntegrityHash checks if metadata contains an integrity hash field
// Note: this is a best-effort check, this is not meant to be exhaustive or a catch-all.
// DO NOT DEPEND ON THESE VALUES IN AUTO-GENERATED CAPABILITIES DEFINITIONS in packages.yaml.
// This should only be used for cross checking assumptions in completion tests, nothing more.
func hasIntegrityHash(metadata interface{}) bool {
	if metadata == nil {
		return false
	}

	v := reflect.ValueOf(metadata)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}

	// only structs have fields
	if v.Kind() != reflect.Struct {
		return false
	}

	// check for common integrity hash field names
	integrityFields := []string{
		"Integrity", "Checksum", "H1Digest",
		"OutputHash", "PkgHash", "ContentHash",
		"PkgHashExt", "Hash", "IntegrityHash",
	}

	for _, fieldName := range integrityFields {
		field := v.FieldByName(fieldName)
		if field.IsValid() && field.Kind() == reflect.String && field.String() != "" {
			return true
		}
	}
	return false
}

// hasFileDigests checks if metadata contains file records with digests.
// Note: this is a best-effort check, this is not meant to be exhaustive or a catch-all.
// DO NOT DEPEND ON THESE VALUES IN AUTO-GENERATED CAPABILITIES DEFINITIONS in packages.yaml.
// This should only be used for cross checking assumptions in completion tests, nothing more.
func hasFileDigests(metadata interface{}) bool {
	if metadata == nil {
		return false
	}

	v := reflect.ValueOf(metadata)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}

	// only structs have fields
	if v.Kind() != reflect.Struct {
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

// hasPopulatedDigest checks if a file record has a populated Digest field
func hasPopulatedDigest(fileRecord reflect.Value) bool {
	// handle pointer to struct
	if fileRecord.Kind() == reflect.Ptr {
		if fileRecord.IsNil() {
			return false
		}
		fileRecord = fileRecord.Elem()
	}

	// only structs have fields
	if fileRecord.Kind() != reflect.Struct {
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

// countDependencyRelationships counts the number of dependency relationships
func countDependencyRelationships(relationships []artifact.Relationship) int {
	count := 0
	for _, rel := range relationships {
		if rel.Type == artifact.DependencyOfRelationship {
			count++
		}
	}
	return count
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// WriteResults writes the collected data to test-fixtures/ directory
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
	if err := writeJSONFile(filename, t.observations); err != nil {
		return err
	}

	return nil
}

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

// WriteResultsIfEnabled writes results if tracking is enabled
func WriteResultsIfEnabled() error {
	tracker := getTracker()
	return tracker.WriteResults()
}
