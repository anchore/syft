package debian

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/blakesmith/ar"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// parseDebArchive parses a Debian package archive (.deb) file and returns the packages it contains.
// A .deb file is an ar archive containing three main files:
// - debian-binary: Version of the .deb format (usually "2.0")
// - control.tar.gz/xz/zst: Contains package metadata (control file, md5sums, conffiles)
// - data.tar.gz/xz/zst: Contains the actual files to be installed (not processed by this cataloger)
//
// This function extracts and processes the control information to create package metadata.
func parseDebArchive(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	log.Debugf("parsing debian archive: %s", reader.RealPath)
	
	arReader := ar.NewReader(reader)
	
	var controlTarReader io.Reader
	var md5sumsContent []byte
	var conffilesContent []byte
	
	// Extract the control.tar.* file from the .deb archive
	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read ar header: %w", err)
		}
		
		log.Debugf("found archive entry: %s", header.Name)
		
		switch {
		case strings.HasPrefix(header.Name, "control.tar"):
			// Read the entire control.tar.* file
			controlTarBytes, err := io.ReadAll(arReader)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read control.tar: %w", err)
			}
			
			// Determine compression type (.tar.gz, .tar.xz, .tar.zst)
			compressionType := detectCompression(header.Name)
			if compressionType == "" {
				return nil, nil, fmt.Errorf("unsupported control file compression: %s", header.Name)
			}
			
			log.Debugf("decompressing control.tar using %s compression", compressionType)
			
			// Decompress the control.tar.* file
			decompressed, err := decompress(controlTarBytes, compressionType)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to decompress control.tar: %w", err)
			}
			
			controlTarReader = bytes.NewReader(decompressed)
			
			// Extract control, md5sums, and conffiles files from control.tar
			tarReader := tar.NewReader(controlTarReader)
			controlFileContent, md5Content, confContent, err := readControlFiles(tarReader)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read control files: %w", err)
			}
			
			if controlFileContent == nil {
				return nil, nil, fmt.Errorf("control file not found in archive")
			}
			
			md5sumsContent = md5Content
			conffilesContent = confContent
			
			// Parse the control file to get package metadata
			metadata, err := parseControlFile(string(controlFileContent))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse control file: %w", err)
			}
			
			log.Debugf("found debian package: %s version %s", metadata.Package, metadata.Version)
			
			// Parse MD5 sums to get file records
			var files []pkg.DpkgFileRecord
			if md5sumsContent != nil {
				files = parseMd5sums(string(md5sumsContent))
				log.Debugf("found %d files with md5sums", len(files))
			}
			
			// Mark config files
			if conffilesContent != nil {
				markConfigFiles(conffilesContent, files)
				log.Debugf("processed conffiles information")
			}
			
			metadata.Files = files
			
			p := newDebPackage(reader.Location, *metadata)
			return []pkg.Package{p}, nil, nil
		}
	}
	
	return nil, nil, errors.New("no valid control file found in .deb package")
}

// detectCompression determines the compression type from the filename
func detectCompression(filename string) string {
	// Remove trailing slash that may appear in AR archive filenames
	cleanName := strings.TrimSuffix(filename, "/")
	
	switch {
	case strings.HasSuffix(cleanName, ".gz"):
		return "gzip"
	case strings.HasSuffix(cleanName, ".xz"):
		return "xz"
	case strings.HasSuffix(cleanName, ".zst"):
		return "zstd"
	default:
		return ""
	}
}

// decompress handles decompression of the control.tar file based on compression type
func decompress(data []byte, compressionType string) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(data)
	var err error
	
	switch compressionType {
	case "gzip":
		gzipReader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	case "xz":
		// Use the xz library from ulikunitz
		xzReader, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create xz reader: %w", err)
		}
		reader = xzReader
	case "zstd":
		// Use the zstd library from klauspost
		zstdDecoder, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd reader: %w", err)
		}
		defer zstdDecoder.Close()
		reader = zstdDecoder
	default:
		return nil, fmt.Errorf("unsupported compression type: %s", compressionType)
	}

	// Read the decompressed data
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}
	
	return decompressed, nil
}

// readControlFiles extracts important files from the control.tar archive
func readControlFiles(tarReader *tar.Reader) (controlFile, md5sums, conffiles []byte, err error) {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		
		switch filepath.Base(header.Name) {
		case "control":
			controlFile, err = io.ReadAll(tarReader)
			if err != nil {
				return nil, nil, nil, err
			}
		case "md5sums":
			md5sums, err = io.ReadAll(tarReader)
			if err != nil {
				return nil, nil, nil, err
			}
		case "conffiles":
			conffiles, err = io.ReadAll(tarReader)
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}
	
	return controlFile, md5sums, conffiles, nil
}

// parseControlFile parses the content of a debian control file into package metadata
func parseControlFile(controlFileContent string) (*pkg.DpkgDBEntry, error) {
	// Reuse the existing dpkg status file parsing logic
	reader := strings.NewReader(controlFileContent)
	
	entries, err := parseDpkgStatus(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse control file: %w", err)
	}
	
	if len(entries) == 0 {
		return nil, fmt.Errorf("no package entries found in control file")
	}
	
	// We expect only one entry from a .deb control file
	return &entries[0], nil
}

// parseMd5sums converts the md5sums file content into DpkgFileRecord entries
func parseMd5sums(md5sumsContent string) []pkg.DpkgFileRecord {
	// Reuse existing md5sums parsing logic
	reader := strings.NewReader(md5sumsContent)
	return parseDpkgMD5Info(reader)
}

// markConfigFiles marks files that are listed in conffiles as configuration files
func markConfigFiles(conffilesContent []byte, files []pkg.DpkgFileRecord) {
	// Parse the conffiles content into DpkgFileRecord entries
	confFiles := parseDpkgConffileInfo(bytes.NewReader(conffilesContent))
	
	// Create a map for quick lookup of config files by path
	configPathMap := make(map[string]struct{})
	for _, confFile := range confFiles {
		configPathMap[confFile.Path] = struct{}{}
	}
	
	// Mark files as config files if they're in the conffiles list
	for i := range files {
		if _, exists := configPathMap[files[i].Path]; exists {
			files[i].IsConfigFile = true
		}
	}
}

// newDebPackage creates a new package from the parsed Debian metadata
func newDebPackage(location file.Location, metadata pkg.DpkgDBEntry) pkg.Package {
	p := pkg.Package{
		Name:      metadata.Package,
		Version:   metadata.Version,
		Type:      pkg.DebPkg,
		Metadata:  metadata,
		Locations: file.NewLocationSet(location),
	}
	
	p.SetID()
	return p
}