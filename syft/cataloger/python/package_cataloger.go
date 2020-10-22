package python

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/syft/scope"
)

const (
	eggMetadataGlob   = "**/*egg-info/PKG-INFO"
	wheelMetadataGlob = "**/*dist-info/METADATA"
)

type PackageCataloger struct{}

// NewPythonPackageCataloger returns a new cataloger for python packages within egg or wheel installation directories.
func NewPythonPackageCataloger() *PackageCataloger {
	return &PackageCataloger{}
}

func (c *PackageCataloger) Name() string {
	return "python-package-cataloger"
}

func (c *PackageCataloger) Catalog(resolver scope.Resolver) ([]pkg.Package, error) {
	// nolint:prealloc
	var fileMatches []file.Reference

	for _, glob := range []string{eggMetadataGlob, wheelMetadataGlob} {
		matches, err := resolver.FilesByGlob(glob)
		if err != nil {
			return nil, fmt.Errorf("failed to find files by glob: %s", glob)
		}
		fileMatches = append(fileMatches, matches...)
	}

	var pkgs []pkg.Package
	for _, ref := range fileMatches {
		p, err := c.catalogEggOrWheel(resolver, ref)
		if err != nil {
			return nil, fmt.Errorf("unable to catalog python package=%+v: %w", ref.Path, err)
		}
		if p != nil {
			pkgs = append(pkgs, *p)
		}
	}
	return pkgs, nil
}

func (c *PackageCataloger) assembleEggOrWheelMetadata(resolver scope.Resolver, metadataRef file.Reference) (*pkg.PythonPackageMetadata, []file.Reference, error) {
	var sources = []file.Reference{metadataRef}

	metadataContents, err := resolver.FileContentsByRef(metadataRef)
	if err != nil {
		return nil, nil, err
	}

	metadata, err := parseWheelOrEggMetadata(metadataRef.Path, strings.NewReader(metadataContents))
	if err != nil {
		return nil, nil, err
	}

	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or the next adjacent lower layer).

	// lets find the RECORD file relative to the directory where the METADATA file resides (in path AND layer structure)
	recordPath := filepath.Join(filepath.Dir(string(metadataRef.Path)), "RECORD")
	recordRef, err := resolver.RelativeFileByPath(metadataRef, recordPath)
	if err != nil {
		return nil, nil, err
	}

	if recordRef != nil {
		sources = append(sources, *recordRef)

		recordContents, err := resolver.FileContentsByRef(*recordRef)
		if err != nil {
			return nil, nil, err
		}

		// parse the record contents
		records, err := parseWheelOrEggRecord(strings.NewReader(recordContents))
		if err != nil {
			return nil, nil, err
		}

		// append the record files list to the metadata
		metadata.Files = records
	}

	// a top_level.txt file specifies the python top-level packages (provided by this python package) installed into site-packages
	parentDir := filepath.Dir(string(metadataRef.Path))
	topLevelPath := filepath.Join(parentDir, "top_level.txt")
	topLevelRef, err := resolver.RelativeFileByPath(metadataRef, topLevelPath)
	if err != nil {
		return nil, nil, err
	}
	if topLevelRef == nil {
		return nil, nil, fmt.Errorf("missing python package top_level.txt (package=%q)", string(metadataRef.Path))
	}

	topLevelContents, err := resolver.FileContentsByRef(*topLevelRef)
	if err != nil {
		return nil, nil, err
	}
	// nolint:prealloc
	var topLevelPackages []string
	scanner := bufio.NewScanner(strings.NewReader(topLevelContents))
	for scanner.Scan() {
		topLevelPackages = append(topLevelPackages, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("could not read python package top_level.txt: %w", err)
	}

	metadata.TopLevelPackages = topLevelPackages

	return &metadata, sources, nil
}

func (c *PackageCataloger) catalogEggOrWheel(resolver scope.Resolver, metadataRef file.Reference) (*pkg.Package, error) {

	metadata, sources, err := c.assembleEggOrWheelMetadata(resolver, metadataRef)
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
		Source:       sources,
		Licenses:     licenses,
		Language:     pkg.Python,
		Type:         pkg.PythonPkg,
		MetadataType: pkg.PythonPackageMetadataType,
		Metadata:     *metadata,
	}, nil
}
