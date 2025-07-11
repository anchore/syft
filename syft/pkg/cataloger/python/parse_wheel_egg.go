package python

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseWheelOrEgg takes the primary metadata file reference and returns the python package it represents. Contained
// fields are governed by the PyPA core metadata specification (https://packaging.python.org/en/latest/specifications/core-metadata/).
func parseWheelOrEgg(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pd, sources, err := assembleEggOrWheelMetadata(resolver, reader.Location)

	if pd == nil {
		return nil, nil, err
	}

	// This can happen for Python 2.7 where it is reported from an egg-info, but Python is
	// the actual runtime, it isn't a "package". The special-casing here allows to skip it
	if pd.Name == "Python" {
		return nil, nil, err
	}

	pkgs := []pkg.Package{
		newPackageForPackage(
			*pd,
			findLicenses(ctx, resolver, *pd),
			sources...,
		),
	}

	return pkgs, nil, err
}

// fetchInstalledFiles finds a corresponding installed-files.txt file for the given python package metadata file and returns the set of file records contained.
func fetchInstalledFiles(resolver file.Resolver, metadataLocation file.Location, sitePackagesRootPath string) (files []pkg.PythonFileRecord, sources []file.Location, retErr error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the installed-files.txt path to the same layer (or the next adjacent lower layer).

	// find the installed-files.txt file relative to the directory where the METADATA file resides (in path AND layer structure)
	installedFilesPath := filepath.Join(filepath.Dir(metadataLocation.RealPath), "installed-files.txt")
	installedFilesRef := resolver.RelativeFileByPath(metadataLocation, installedFilesPath)

	if installedFilesRef != nil {
		sources = append(sources, installedFilesRef.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))

		installedFilesContents, err := resolver.FileContentsByLocation(*installedFilesRef)
		if err != nil {
			return nil, nil, err
		}
		defer internal.CloseAndLogError(installedFilesContents, installedFilesPath)

		// parse the installed-files contents
		installedFiles, err := parseInstalledFiles(installedFilesContents, metadataLocation.RealPath, sitePackagesRootPath)
		if err != nil {
			retErr = unknown.Newf(*installedFilesRef, "unable to parse installed-files.txt for python package: %w", retErr)
		}

		files = append(files, installedFiles...)
	}
	return files, sources, nil
}

// fetchRecordFiles finds a corresponding RECORD file for the given python package metadata file and returns the set of file records contained.
func fetchRecordFiles(resolver file.Resolver, metadataLocation file.Location) (files []pkg.PythonFileRecord, sources []file.Location, retErr error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or the next adjacent lower layer).

	// find the RECORD file relative to the directory where the METADATA file resides (in path AND layer structure)
	recordPath := filepath.Join(filepath.Dir(metadataLocation.RealPath), "RECORD")
	recordRef := resolver.RelativeFileByPath(metadataLocation, recordPath)

	if recordRef != nil {
		sources = append(sources, recordRef.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))

		recordContents, err := resolver.FileContentsByLocation(*recordRef)
		if err != nil {
			return nil, nil, err
		}
		defer internal.CloseAndLogError(recordContents, recordPath)

		// parse the record contents
		var records []pkg.PythonFileRecord
		records, retErr = parseWheelOrEggRecord(file.NewLocationReadCloser(*recordRef, recordContents))

		files = append(files, records...)
	}
	return files, sources, retErr
}

// fetchTopLevelPackages finds a corresponding top_level.txt file for the given python package metadata file and returns the set of package names contained.
func fetchTopLevelPackages(resolver file.Resolver, metadataLocation file.Location) (pkgs []string, sources []file.Location, err error) {
	// a top_level.txt file specifies the python top-level packages (provided by this python package) installed into site-packages
	parentDir := filepath.Dir(metadataLocation.RealPath)
	topLevelPath := filepath.Join(parentDir, "top_level.txt")
	topLevelLocation := resolver.RelativeFileByPath(metadataLocation, topLevelPath)

	if topLevelLocation == nil {
		return nil, nil, nil
	}

	sources = append(sources, topLevelLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))

	topLevelContents, err := resolver.FileContentsByLocation(*topLevelLocation)
	if err != nil {
		return nil, nil, err
	}
	defer internal.CloseAndLogError(topLevelContents, topLevelLocation.AccessPath)

	scanner := bufio.NewScanner(topLevelContents)
	for scanner.Scan() {
		pkgs = append(pkgs, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return pkgs, sources, nil
}

type directURLOrigin struct {
	URL         string      `json:"url"`
	VCSInfo     vcsInfo     `json:"vcs_info"`
	ArchiveInfo archiveInfo `json:"archive_info"`
	DirInfo     dirInfo     `json:"dir_info"`
}

type dirInfo struct {
	Editable bool `json:"editable"`
}

type archiveInfo struct {
	Hash string `json:"hash"`
}

type vcsInfo struct {
	CommitID          string `json:"commit_id"`
	VCS               string `json:"vcs"`
	RequestedRevision string `json:"requested_revision"`
}

func fetchDirectURLData(resolver file.Resolver, metadataLocation file.Location) (d *pkg.PythonDirectURLOriginInfo, sources []file.Location, err error) {
	parentDir := filepath.Dir(metadataLocation.RealPath)
	directURLPath := filepath.Join(parentDir, "direct_url.json")
	directURLLocation := resolver.RelativeFileByPath(metadataLocation, directURLPath)

	if directURLLocation == nil {
		return nil, nil, nil
	}

	sources = append(sources, directURLLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))

	directURLContents, err := resolver.FileContentsByLocation(*directURLLocation)
	if err != nil {
		return nil, nil, err
	}
	defer internal.CloseAndLogError(directURLContents, directURLLocation.AccessPath)

	buffer, err := io.ReadAll(directURLContents)
	if err != nil {
		return nil, nil, err
	}

	var directURLJson directURLOrigin
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
func assembleEggOrWheelMetadata(resolver file.Resolver, metadataLocation file.Location) (*parsedData, []file.Location, error) {
	var sources = []file.Location{
		metadataLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	}

	metadataContents, err := resolver.FileContentsByLocation(metadataLocation)
	if err != nil {
		return nil, nil, err
	}
	defer internal.CloseAndLogError(metadataContents, metadataLocation.AccessPath)

	pd, err := parseWheelOrEggMetadata(file.NewLocationReadCloser(metadataLocation, metadataContents))
	if err != nil {
		return nil, nil, err
	}

	if pd.Name == "" {
		return nil, nil, nil
	}

	// attach any python files found for the given wheel/egg installation
	var errs error
	r, s, err := fetchRecordFiles(resolver, metadataLocation)
	if err != nil {
		errs = unknown.Joinf(errs, "could not read python package RECORD file: %w", err)
	}
	if len(r) == 0 {
		r, s, err = fetchInstalledFiles(resolver, metadataLocation, pd.SitePackagesRootPath)
		if err != nil {
			errs = unknown.Joinf(errs, "could not read python package installed-files.txt: %w", err)
		}
	}

	sources = append(sources, s...)
	pd.Files = r

	// attach any top-level package names found for the given wheel/egg installation
	p, s, err := fetchTopLevelPackages(resolver, metadataLocation)
	if err != nil {
		errs = unknown.Joinf(errs, "could not read python package top_level.txt: %w", err)
	}
	sources = append(sources, s...)
	pd.TopLevelPackages = p

	// attach any direct-url package data found for the given wheel/egg installation
	d, s, err := fetchDirectURLData(resolver, metadataLocation)
	if err != nil {
		errs = unknown.Joinf(errs, "could not read python package direct_url.json: %w", err)
	}

	sources = append(sources, s...)
	pd.DirectURLOrigin = d
	return &pd, sources, errs
}

func findLicenses(ctx context.Context, resolver file.Resolver, m parsedData) pkg.LicenseSet {
	var licenseSet pkg.LicenseSet

	licenseLocations := file.NewLocationSet()
	if m.LicenseFilePath != "" {
		locs, err := resolver.FilesByPath(m.LicenseFilePath)
		if err != nil {
			log.WithFields("error", err, "path", m.LicenseFilePath).Trace("unable to resolve python license file")
		} else {
			licenseLocations.Add(locs...)
		}
	}

	switch {
	case m.LicenseExpression != "" || m.Licenses != "":
		licenseSet = getLicenseSetFromValues(ctx, licenseLocations.ToSlice(), m.LicenseExpression, m.Licenses)
	case !licenseLocations.Empty():
		licenseSet = getLicenseSetFromFiles(ctx, resolver, licenseLocations.ToSlice()...)

	default:
		// search for known license paths from RECORDS file
		licenseNames := strset.New()
		for _, n := range licenses.FileNames() {
			licenseNames.Add(strings.ToLower(n))
		}
		parent := path.Base(path.Dir(m.DistInfoLocation.Path()))
		candidatePaths := strset.New()
		for _, f := range m.Files {
			if !strings.HasPrefix(f.Path, parent) || strings.Count(f.Path, "/") > 1 {
				continue
			}

			if licenseNames.Has(strings.ToLower(filepath.Base(f.Path))) {
				candidatePaths.Add(path.Join(m.SitePackagesRootPath, f.Path))
			}
		}

		paths := candidatePaths.List()
		sort.Strings(paths)
		locationSet := file.NewLocationSet()
		for _, p := range paths {
			locs, err := resolver.FilesByPath(p)
			if err != nil {
				log.WithFields("error", err, "path", p).Trace("unable to resolve python license in dist-info")
				continue
			}
			locationSet.Add(locs...)
		}

		licenseSet = getLicenseSetFromFiles(ctx, resolver, locationSet.ToSlice()...)
	}
	return licenseSet
}

func getLicenseSetFromValues(ctx context.Context, locations []file.Location, licenseValues ...string) pkg.LicenseSet {
	if len(locations) == 0 {
		return pkg.NewLicenseSet(pkg.NewLicensesFromValuesWithContext(ctx, licenseValues...)...)
	}

	licenseSet := pkg.NewLicenseSet()
	for _, value := range licenseValues {
		if value == "" {
			continue
		}

		licenseSet.Add(pkg.NewLicenseFromLocationsWithContext(ctx, value, locations...))
	}
	return licenseSet
}

func getLicenseSetFromFiles(ctx context.Context, resolver file.Resolver, locations ...file.Location) pkg.LicenseSet {
	licenseSet := pkg.NewLicenseSet()
	for _, loc := range locations {
		licenseSet.Add(getLicenseSetFromFile(ctx, resolver, loc)...)
	}
	return licenseSet
}

func getLicenseSetFromFile(ctx context.Context, resolver file.Resolver, location file.Location) []pkg.License {
	metadataContents, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.WithFields("error", err, "path", location.Path()).Trace("unable to read file contents")
		return nil
	}
	defer internal.CloseAndLogError(metadataContents, location.Path())
	return pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(location, metadataContents))
}
