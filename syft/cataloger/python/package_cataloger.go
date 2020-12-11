package python

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/syft/source"
)

const (
	eggMetadataGlob   = "**/*egg-info/PKG-INFO"
	wheelMetadataGlob = "**/*dist-info/METADATA"
)

type pythonPackageData struct {
	Metadata   source.FileData
	FileRecord *source.FileData
	TopPackage *source.FileData
}

type PackageCataloger struct{}

// NewPythonPackageCataloger returns a new cataloger for python packages within egg or wheel installation directories.
func NewPythonPackageCataloger() *PackageCataloger {
	return &PackageCataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *PackageCataloger) Name() string {
	return "python-package-cataloger"
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing python egg and wheel installations.
func (c *PackageCataloger) Catalog(resolver source.Resolver) ([]pkg.Package, error) {
	entries, err := c.getPythonPackageEntries(resolver)
	if err != nil {
		return nil, err
	}

	var packages []pkg.Package
	for _, entry := range entries {
		p, err := c.catalogEggOrWheel(entry)
		if err != nil {
			return nil, fmt.Errorf("unable to catalog python package=%+v: %w", entry.Metadata.Location.Path, err)
		}
		if p != nil {
			packages = append(packages, *p)
		}
	}

	return packages, nil
}

func (c *PackageCataloger) getPythonPackageEntries(resolver source.Resolver) ([]*pythonPackageData, error) {
	var metadataLocations []source.Location

	// find all primary record paths
	matches, err := resolver.FilesByGlob(eggMetadataGlob, wheelMetadataGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find files by glob: %w", err)
	}
	metadataLocations = append(metadataLocations, matches...)

	// for every primary record path, craft all secondary record paths and build a request object to gather all file contents for each record
	var requester = source.NewContentRequester()
	var entries = make([]*pythonPackageData, len(metadataLocations))
	for i, metadataLocation := range metadataLocations {
		// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
		// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
		// to reconcile the RECORD path to the same layer (or the next adjacent lower layer). The same is true with
		// the top_level.txt file.

		// lets find the RECORD file relative to the directory where the METADATA file resides (in path AND layer structure)
		recordPath := filepath.Join(filepath.Dir(metadataLocation.Path), "RECORD")
		recordLocation := resolver.RelativeFileByPath(metadataLocation, recordPath)

		// a top_level.txt file specifies the python top-level packages (provided by this python package) installed into site-packages
		parentDir := filepath.Dir(metadataLocation.Path)
		topLevelPath := filepath.Join(parentDir, "top_level.txt")
		topLevelLocation := resolver.RelativeFileByPath(metadataLocation, topLevelPath)

		// build an entry that will later be populated with contents when the request is executed
		entry := &pythonPackageData{
			Metadata: source.FileData{
				Location: metadataLocation,
			},
		}

		requester.Add(&entry.Metadata)

		if recordLocation != nil {
			entry.FileRecord = &source.FileData{
				Location: *recordLocation,
			}
			requester.Add(entry.FileRecord)
		}

		if topLevelLocation != nil {
			entry.TopPackage = &source.FileData{
				Location: *topLevelLocation,
			}
			requester.Add(entry.TopPackage)
		}

		// keep the entry for processing later
		entries[i] = entry
	}

	// return the set of entries and execute the request for fetching contents
	return entries, requester.Execute(resolver)
}

// catalogEggOrWheel takes the primary metadata file reference and returns the python package it represents.
func (c *PackageCataloger) catalogEggOrWheel(entry *pythonPackageData) (*pkg.Package, error) {
	metadata, sources, err := c.assembleEggOrWheelMetadata(entry)
	if err != nil {
		return nil, err
	}

	var licenses []string
	if metadata.License != "" {
		licenses = []string{metadata.License}
	}

	return &pkg.Package{
		Name:         metadata.Name,
		Version:      metadata.Version,
		FoundBy:      c.Name(),
		Locations:    sources,
		Licenses:     licenses,
		Language:     pkg.Python,
		Type:         pkg.PythonPkg,
		MetadataType: pkg.PythonPackageMetadataType,
		Metadata:     *metadata,
	}, nil
}

// assembleEggOrWheelMetadata discovers and accumulates python package metadata from multiple file sources and returns a single metadata object as well as a list of files where the metadata was derived from.
func (c *PackageCataloger) assembleEggOrWheelMetadata(entry *pythonPackageData) (*pkg.PythonPackageMetadata, []source.Location, error) {
	var sources = []source.Location{entry.Metadata.Location}

	metadata, err := parseWheelOrEggMetadata(entry.Metadata.Location.Path, strings.NewReader(entry.Metadata.Contents))
	if err != nil {
		return nil, nil, err
	}

	// attach any python files found for the given wheel/egg installation
	r, s, err := c.fetchRecordFiles(entry.FileRecord)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.Files = r

	// attach any top-level package names found for the given wheel/egg installation
	p, s, err := c.fetchTopLevelPackages(entry.TopPackage)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.TopLevelPackages = p

	return &metadata, sources, nil
}

// fetchRecordFiles finds a corresponding RECORD file for the given python package metadata file and returns the set of file records contained.
func (c *PackageCataloger) fetchRecordFiles(entry *source.FileData) (files []pkg.PythonFileRecord, sources []source.Location, err error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or the next adjacent lower layer).

	if entry != nil {
		sources = append(sources, entry.Location)

		// parse the record contents
		records, err := parseWheelOrEggRecord(strings.NewReader(entry.Contents))
		if err != nil {
			return nil, nil, err
		}

		files = append(files, records...)
	}
	return files, sources, nil
}

// fetchTopLevelPackages finds a corresponding top_level.txt file for the given python package metadata file and returns the set of package names contained.
func (c *PackageCataloger) fetchTopLevelPackages(entry *source.FileData) (pkgs []string, sources []source.Location, err error) {
	if entry == nil {
		log.Warnf("missing python package top_level.txt (package=!!)")
		return nil, nil, nil
	}

	sources = append(sources, entry.Location)

	scanner := bufio.NewScanner(strings.NewReader(entry.Contents))
	for scanner.Scan() {
		pkgs = append(pkgs, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("could not read python package top_level.txt: %w", err)
	}

	return pkgs, sources, nil
}
