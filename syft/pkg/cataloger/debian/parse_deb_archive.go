package debian

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blakesmith/ar"
	"github.com/mholt/archives"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseDebArchive parses a Debian package archive (.deb) file and returns the packages it contains.
// A .deb file is an ar archive containing three main files:
// - debian-binary: Version of the .deb format (usually "2.0")
// - control.tar.gz/xz/zst: Contains package metadata (control file, md5sums, conffiles)
// - data.tar.gz/xz/zst: Contains the actual files to be installed (not processed by this cataloger)
//
// This function extracts and processes the control information to create package metadata.
func parseDebArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	validatedReader, err := newValidatedArReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ar archive: %w", err)
	}

	arReader := ar.NewReader(validatedReader)

	var metadata *pkg.DpkgArchiveEntry
	var licenses []string
	var ctrlLicenses []string
	var unknownErr error
	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read ar header: %w", err)
		}

		switch {
		case strings.HasPrefix(header.Name, "control.tar"):
			// Decompress the control.tar.* file
			dcReader, err := decompressionStream(ctx, arReader, header.Name)
			if err != nil {
				return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to decompress control.tar.* file: %w", err))
			}
			metadata, ctrlLicenses, err = processControlTar(dcReader)
			if err != nil {
				return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to process control.tar.* file: %w", err))
			}
		case strings.HasPrefix(header.Name, "data.tar"):
			// Decompress the data.tar.* file
			dcReader, err := decompressionStream(ctx, arReader, header.Name)
			if err != nil {
				return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to decompress data.tar.* file: %w", err))
			}
			licenses, err = processDataTar(dcReader)
			if err != nil {
				unknownErr = unknown.Append(unknownErr, reader.Location, fmt.Errorf("failed to process data.tar.* file: %w", err))
			}
		}
	}

	if metadata == nil {
		return nil, nil, unknown.New(reader.Location, fmt.Errorf("no application found described in .dpkg archive"))
	}

	if len(licenses) == 0 && len(ctrlLicenses) > 0 {
		licenses = ctrlLicenses
	}

	return []pkg.Package{
		newDebArchivePackage(ctx, reader.Location, *metadata, licenses),
	}, nil, nil
}

// this is the pattern you'd expect to see in a tar header for a debian package license file ()
var archiveHeaderLicensePathPattern = regexp.MustCompile(`^\.?/usr/share/doc/[^/]+/copyright$`)

func processDataTar(dcReader io.ReadCloser) ([]string, error) {
	defer internal.CloseAndLogError(dcReader, "")
	var licenses []string

	tarReader := tar.NewReader(dcReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return licenses, err
		}

		// look for /usr/share/docs/*/copyright files, parse each one for license claims
		// TODO: in the future we can add archive sub indexes to the locations to see where within
		// the dpkg archive the license was found
		if archiveHeaderLicensePathPattern.MatchString(header.Name) {
			licenses = append(licenses, parseLicensesFromCopyright(tarReader)...)
		}
	}

	return licenses, nil
}

func processControlTar(dcReader io.ReadCloser) (*pkg.DpkgArchiveEntry, []string, error) {
	defer internal.CloseAndLogError(dcReader, "")

	tarReader := tar.NewReader(dcReader)

	var metadata *pkg.DpkgArchiveEntry
	var files []pkg.DpkgFileRecord
	var confFileRecords []pkg.DpkgFileRecord
	var licenses []string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read control tar: %w", err)
		}

		switch filepath.Base(header.Name) {
		case "control":
			// parseDpkgStatus already streams via bufio.Reader
			entries, err := parseDpkgStatus(tarReader)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse control file: %w", err)
			}
			if len(entries) == 0 {
				return nil, nil, fmt.Errorf("no package entries found in control file")
			}
			entry := pkg.DpkgArchiveEntry(entries[0].toDpkgEntry())
			licenses = normalizeControlLicenses(entries[0].License)
			metadata = &entry
		case "md5sums":
			// parseDpkgMD5Info already streams via bufio.Scanner
			files = parseDpkgMD5Info(tarReader)
		case "conffiles":
			// parseDpkgConffileInfo already streams via bufio.Scanner
			confFileRecords = parseDpkgConffileInfo(tarReader)
		}
	}

	if metadata == nil {
		return nil, nil, fmt.Errorf("control file not found in archive")
	}

	if len(confFileRecords) > 0 && len(files) > 0 {
		configPaths := make(map[string]struct{}, len(confFileRecords))
		for _, cf := range confFileRecords {
			configPaths[cf.Path] = struct{}{}
		}
		for i, f := range files {
			if _, isConfig := configPaths[f.Path]; isConfig {
				files[i].IsConfigFile = true
			}
		}
	}

	metadata.Files = files
	return metadata, licenses, nil
}

func normalizeControlLicenses(rawLicense string) []string {
	parts := strings.Split(rawLicense, "&")
	licenses := make([]string, 0, len(parts))

	for _, part := range parts {
		license := strings.TrimSpace(part)
		if license == "" {
			continue
		}

		if strings.HasPrefix(license, "(") && strings.HasSuffix(license, ")") {
			license = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(license, ")"), "("))
		}

		if strings.Contains(license, "|") {
			alternatives := strings.Split(license, "|")
			for i := range alternatives {
				alternatives[i] = strings.TrimSpace(alternatives[i])
			}
			license = strings.Join(alternatives, " or ")
		}

		licenses = append(licenses, license)
	}

	return licenses
}

func newValidatedArReader(reader io.ReadCloser) (io.ReadCloser, error) {
	prefix := make([]byte, len(ar.GLOBAL_HEADER))
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, fmt.Errorf("failed to read ar header: %w", err)
	}

	if !bytes.Equal(prefix, []byte(ar.GLOBAL_HEADER)) {
		return nil, fmt.Errorf("expected ar header %q, got %q", string(ar.GLOBAL_HEADER), string(prefix))
	}

	return io.NopCloser(io.MultiReader(bytes.NewReader(prefix), reader)), nil
}

func decompressionStream(ctx context.Context, r io.Reader, filePath string) (io.ReadCloser, error) {
	format, stream, err := archives.Identify(ctx, filePath, r)
	if err != nil {
		return nil, fmt.Errorf("failed to identify compression format: %w", err)
	}

	decompressor, ok := format.(archives.Decompressor)
	if !ok {
		return nil, fmt.Errorf("file format does not support decompression: %s", filePath)
	}

	rc, err := decompressor.OpenReader(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to create decompression reader: %w", err)
	}

	return rc, nil
}
