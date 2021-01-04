package python

import (
	"bufio"
	"fmt"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/syft/source"
)

const (
	eggMetadataGlob     = "**/*egg-info/PKG-INFO"
	eggFileMetadataGlob = "**/*.egg-info"
	wheelMetadataGlob   = "**/*dist-info/METADATA"
)

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
	entries, err := c.getPackageEntries(resolver)
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

// getPackageEntries fetches the contents for all python packages within the given resolver.
func (c *PackageCataloger) getPackageEntries(resolver source.Resolver) ([]*packageEntry, error) {
	var metadataLocations []source.Location

	// find all primary record paths
	matches, err := resolver.FilesByGlob(eggMetadataGlob, eggFileMetadataGlob, wheelMetadataGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find files by glob: %w", err)
	}
	metadataLocations = append(metadataLocations, matches...)

	// for every primary record path, craft all secondary record paths and build a request object to gather all file contents for each record
	requester := source.NewContentRequester()
	entries := make([]*packageEntry, len(metadataLocations))
	for i, metadataLocation := range metadataLocations {
		// build the entry to process (holding only path information)
		entry := newPackageEntry(resolver, metadataLocation)

		// populate the data onto the requester object
		requester.Add(&entry.Metadata)
		if entry.FileRecord != nil {
			requester.Add(entry.FileRecord)
		}
		if entry.TopPackage != nil {
			requester.Add(entry.TopPackage)
		}

		// keep track of the entry for later package processing
		entries[i] = entry
	}

	// return the set of entries and execute the request for fetching contents
	return entries, requester.Execute(resolver)
}

// catalogEggOrWheel takes the primary metadata file reference and returns the python package it represents.
func (c *PackageCataloger) catalogEggOrWheel(entry *packageEntry) (*pkg.Package, error) {
	metadata, sources, err := c.assembleEggOrWheelMetadata(entry)
	if err != nil {
		return nil, err
	}

	// This can happen for Python 2.7 where it is reported from an egg-info, but Python is
	// the actual runtime, it isn't a "package". The special-casing here allows to skip it
	if metadata.Name == "Python" {
		return nil, nil
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
func (c *PackageCataloger) assembleEggOrWheelMetadata(entry *packageEntry) (*pkg.PythonPackageMetadata, []source.Location, error) {
	var sources = []source.Location{entry.Metadata.Location}

	metadata, err := parseWheelOrEggMetadata(entry.Metadata.Location.Path, entry.Metadata.Contents)
	if err != nil {
		return nil, nil, err
	}

	// attach any python files found for the given wheel/egg installation
	r, s, err := c.processRecordFiles(entry.FileRecord)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.Files = r

	// attach any top-level package names found for the given wheel/egg installation
	p, s, err := c.processTopLevelPackages(entry.TopPackage)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.TopLevelPackages = p

	return &metadata, sources, nil
}

// processRecordFiles takes a corresponding RECORD file for the given python package metadata file and returns the set of file records contained.
func (c *PackageCataloger) processRecordFiles(entry *source.FileData) (files []pkg.PythonFileRecord, sources []source.Location, err error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or the next adjacent lower layer).

	if entry != nil {
		sources = append(sources, entry.Location)

		// parse the record contents
		records, err := parseWheelOrEggRecord(entry.Contents)
		if err != nil {
			return nil, nil, err
		}

		files = append(files, records...)
	}
	return files, sources, nil
}

// processTopLevelPackages takes a corresponding top_level.txt file for the given python package metadata file and returns the set of package names contained.
func (c *PackageCataloger) processTopLevelPackages(entry *source.FileData) (pkgs []string, sources []source.Location, err error) {
	if entry == nil {
		return nil, nil, nil
	}

	sources = append(sources, entry.Location)

	scanner := bufio.NewScanner(entry.Contents)
	for scanner.Scan() {
		pkgs = append(pkgs, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("could not read python package top_level.txt: %w", err)
	}

	return pkgs, sources, nil
}
