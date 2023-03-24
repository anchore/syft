package python

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

// parseWheelOrEgg takes the primary metadata file reference and returns the python package it represents.
func parseWheelOrEgg(resolver source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	metadata, sources, err := assembleEggOrWheelMetadata(resolver, reader.Location)
	if err != nil {
		return nil, nil, err
	}
	if metadata == nil {
		return nil, nil, nil
	}

	// This can happen for Python 2.7 where it is reported from an egg-info, but Python is
	// the actual runtime, it isn't a "package". The special-casing here allows to skip it
	if metadata.Name == "Python" {
		return nil, nil, nil
	}

	pkgs := []pkg.Package{newPackageForPackage(*metadata, sources...)}

	return pkgs, nil, nil
}

// fetchRecordFiles finds a corresponding installed-files.txt file for the given python package metadata file and returns the set of file records contained.
func fetchInstalledFiles(resolver source.FileResolver, metadataLocation source.Location, sitePackagesRootPath string) (files []pkg.PythonFileRecord, sources []source.Location, err error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the installed-files.txt path to the same layer (or the next adjacent lower layer).

	// find the installed-files.txt file relative to the directory where the METADATA file resides (in path AND layer structure)
	installedFilesPath := filepath.Join(filepath.Dir(metadataLocation.RealPath), "installed-files.txt")
	installedFilesRef := resolver.RelativeFileByPath(metadataLocation, installedFilesPath)

	if installedFilesRef != nil {
		sources = append(sources, *installedFilesRef)

		installedFilesContents, err := resolver.FileContentsByLocation(*installedFilesRef)
		if err != nil {
			return nil, nil, err
		}
		defer internal.CloseAndLogError(installedFilesContents, installedFilesPath)

		// parse the installed-files contents
		installedFiles, err := parseInstalledFiles(installedFilesContents, metadataLocation.RealPath, sitePackagesRootPath)
		if err != nil {
			log.Warnf("unable to parse installed-files.txt for python package=%+v: %w", metadataLocation.RealPath, err)
			return files, sources, nil
		}

		files = append(files, installedFiles...)
	}
	return files, sources, nil
}

// fetchRecordFiles finds a corresponding RECORD file for the given python package metadata file and returns the set of file records contained.
func fetchRecordFiles(resolver source.FileResolver, metadataLocation source.Location) (files []pkg.PythonFileRecord, sources []source.Location, err error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or the next adjacent lower layer).

	// find the RECORD file relative to the directory where the METADATA file resides (in path AND layer structure)
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
		records := parseWheelOrEggRecord(recordContents)

		files = append(files, records...)
	}
	return files, sources, nil
}

// fetchTopLevelPackages finds a corresponding top_level.txt file for the given python package metadata file and returns the set of package names contained.
func fetchTopLevelPackages(resolver source.FileResolver, metadataLocation source.Location) (pkgs []string, sources []source.Location, err error) {
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

func fetchDirectURLData(resolver source.FileResolver, metadataLocation source.Location) (d *pkg.PythonDirectURLOriginInfo, sources []source.Location, err error) {
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

	buffer, err := io.ReadAll(directURLContents)
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
func assembleEggOrWheelMetadata(resolver source.FileResolver, metadataLocation source.Location) (*pkg.PythonPackageMetadata, []source.Location, error) {
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

	if metadata.Name == "" {
		return nil, nil, nil
	}

	// attach any python files found for the given wheel/egg installation
	r, s, err := fetchRecordFiles(resolver, metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	if len(r) == 0 {
		r, s, err = fetchInstalledFiles(resolver, metadataLocation, metadata.SitePackagesRootPath)
		if err != nil {
			return nil, nil, err
		}
	}

	sources = append(sources, s...)
	metadata.Files = r

	// attach any top-level package names found for the given wheel/egg installation
	p, s, err := fetchTopLevelPackages(resolver, metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.TopLevelPackages = p

	// attach any direct-url package data found for the given wheel/egg installation
	d, s, err := fetchDirectURLData(resolver, metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	sources = append(sources, s...)
	metadata.DirectURLOrigin = d

	return &metadata, sources, nil
}
