package python

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/syft/artifact"
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
func (c *PackageCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var fileMatches []source.Location

	for _, glob := range []string{eggMetadataGlob, wheelMetadataGlob, eggFileMetadataGlob} {
		matches, err := resolver.FilesByGlob(glob)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find files by glob: %s", glob)
		}
		fileMatches = append(fileMatches, matches...)
	}

	var pkgs []pkg.Package
	for _, location := range fileMatches {
		p, err := c.catalogEggOrWheel(resolver, location)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to catalog python package=%+v: %w", location.RealPath, err)
		}
		if p != nil {
			pkgs = append(pkgs, *p)
		}
	}
	return pkgs, nil, nil
}

// catalogEggOrWheel takes the primary metadata file reference and returns the python package it represents.
func (c *PackageCataloger) catalogEggOrWheel(resolver source.FileResolver, metadataLocation source.Location) (*pkg.Package, error) {
	metadata, sources, err := c.assembleEggOrWheelMetadata(resolver, metadataLocation)
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

	p := &pkg.Package{
		Name:         metadata.Name,
		Version:      metadata.Version,
		FoundBy:      c.Name(),
		Locations:    source.NewLocationSet(sources...),
		Licenses:     licenses,
		Language:     pkg.Python,
		Type:         pkg.PythonPkg,
		MetadataType: pkg.PythonPackageMetadataType,
		Metadata:     *metadata,
	}

	p.SetID()

	return p, nil
}

// fetchRecordFiles finds a corresponding RECORD file for the given python package metadata file and returns the set of file records contained.
func (c *PackageCataloger) fetchRecordFiles(resolver source.FileResolver, metadataLocation source.Location) (files []pkg.PythonFileRecord, sources []source.Location, err error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or the next adjacent lower layer).

	// lets find the RECORD file relative to the directory where the METADATA file resides (in path AND layer structure)
	recordPath := filepath.Join(filepath.Dir(metadataLocation.RealPath), "RECORD")
	recordRef := resolver.RelativeFileByPath(metadataLocation, recordPath)

	if recordRef != nil {
		sources = append(sources, *recordRef)

		recordContents, err := resolver.FileContentsByLocation(*recordRef)
		if err != nil {
			return nil, nil, err
		}
		defer internal.CloseAndLogError(recordContents, recordPath)

		// parse the record contents
		records, err := parseWheelOrEggRecord(recordContents)
		if err != nil {
			return nil, nil, err
		}

		files = append(files, records...)
	}
	return files, sources, nil
}

// fetchTopLevelPackages finds a corresponding top_level.txt file for the given python package metadata file and returns the set of package names contained.
func (c *PackageCataloger) fetchTopLevelPackages(resolver source.FileResolver, metadataLocation source.Location) (pkgs []string, sources []source.Location, err error) {
	// a top_level.txt file specifies the python top-level packages (provided by this python package) installed into site-packages
	parentDir := filepath.Dir(metadataLocation.RealPath)
	topLevelPath := filepath.Join(parentDir, "top_level.txt")
	topLevelLocation := resolver.RelativeFileByPath(metadataLocation, topLevelPath)

	if topLevelLocation == nil {
		return nil, nil, nil
	}

	sources = append(sources, *topLevelLocation)

	topLevelContents, err := resolver.FileContentsByLocation(*topLevelLocation)
	if err != nil {
		return nil, nil, err
	}
	defer internal.CloseAndLogError(topLevelContents, topLevelLocation.VirtualPath)

	scanner := bufio.NewScanner(topLevelContents)
	for scanner.Scan() {
		pkgs = append(pkgs, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("could not read python package top_level.txt: %w", err)
	}

	return pkgs, sources, nil
}

func (c *PackageCataloger) fetchDirectURLData(resolver source.FileResolver, metadataLocation source.Location) (d *pkg.PythonDirectURLOriginInfo, sources []source.Location, err error) {
	parentDir := filepath.Dir(metadataLocation.RealPath)
	directURLPath := filepath.Join(parentDir, "direct_url.json")
	directURLLocation := resolver.RelativeFileByPath(metadataLocation, directURLPath)

	if directURLLocation == nil {
		return nil, nil, nil
	}

	sources = append(sources, *directURLLocation)

	directURLContents, err := resolver.FileContentsByLocation(*directURLLocation)
	if err != nil {
		return nil, nil, err
	}
	defer internal.CloseAndLogError(directURLContents, directURLLocation.VirtualPath)

	buffer, err := ioutil.ReadAll(directURLContents)
	if err != nil {
		return nil, nil, err
	}

	var directURLJson pkg.DirectURLOrigin
	if err := json.Unmarshal(buffer, &directURLJson); err != nil {
		return nil, nil, err
	}

	return &pkg.PythonDirectURLOriginInfo{
		URL:      directURLJson.URL,
		CommitID: directURLJson.VCSInfo.CommitID,
		VCS:      directURLJson.VCSInfo.VCS,
	}, sources, nil
}

// assembleEggOrWheelMetadata discovers and accumulates python package metadata from multiple file sources and returns a single metadata object as well as a list of files where the metadata was derived from.
func (c *PackageCataloger) assembleEggOrWheelMetadata(resolver source.FileResolver, metadataLocation source.Location) (*pkg.PythonPackageMetadata, []source.Location, error) {
	var sources = []source.Location{metadataLocation}

	metadataContents, err := resolver.FileContentsByLocation(metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	defer internal.CloseAndLogError(metadataContents, metadataLocation.VirtualPath)

	metadata, err := parseWheelOrEggMetadata(metadataLocation.RealPath, metadataContents)
	if err != nil {
		return nil, nil, err
	}

	// attach any python files found for the given wheel/egg installation
	r, s, err := c.fetchRecordFiles(resolver, metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.Files = r

	// attach any top-level package names found for the given wheel/egg installation
	p, s, err := c.fetchTopLevelPackages(resolver, metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.TopLevelPackages = p

	// attach any direct-url package data found for the given wheel/egg installation
	d, s, err := c.fetchDirectURLData(resolver, metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.DirectURLOrigin = d

	return &metadata, sources, nil
}
