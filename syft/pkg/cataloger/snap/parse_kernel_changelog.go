package snap

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// kernelVersionInfo holds parsed kernel version information
type kernelVersionInfo struct {
	baseVersion    string // e.g., "5.4.0-195"
	releaseVersion string // e.g., "215"
	fullVersion    string // e.g., "5.4.0-195.215"
	majorVersion   string // e.g., "5.4"
}

// parseKernelChangelog parses changelog files from kernel snaps to extract kernel version.
// The changelog is gzip-compressed and may be very large, so we stream it line-by-line
// rather than reading it entirely into memory.
func parseKernelChangelog(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gzip reader for changelog: %w", err)
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)

	// read the first line to extract kernel version
	// Format: "linux (5.4.0-195.215) focal; urgency=medium"
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("failed to read changelog content: %w", err)
		}
		return nil, nil, fmt.Errorf("changelog file is empty")
	}

	versionInfo, err := extractKernelVersion(scanner.Text())
	if err != nil {
		return nil, nil, err
	}

	snapMetadata := pkg.SnapEntry{
		SnapType: pkg.SnapTypeKernel,
	}

	packages := createMainKernelPackage(versionInfo, snapMetadata, reader.Location)

	// stream remaining lines looking for the base kernel entry
	baseKernelEntry := fmt.Sprintf("%s/linux:", strings.ReplaceAll(versionInfo.releaseVersion, ";", "/"))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, baseKernelEntry) {
			if basePackage := parseBaseKernelLine(line, versionInfo.majorVersion, snapMetadata, reader.Location); basePackage != nil {
				packages = append(packages, *basePackage)
			}
			break
		}
	}

	return packages, nil, nil
}

// extractKernelVersion parses version information from the first changelog line
func extractKernelVersion(firstLine string) (*kernelVersionInfo, error) {
	// Format: "linux (5.4.0-195.215) focal; urgency=medium"
	kernelVersionRegex := regexp.MustCompile(`linux \(([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)\.([0-9]+)\)`)
	matches := kernelVersionRegex.FindStringSubmatch(firstLine)

	if len(matches) < 3 {
		return nil, fmt.Errorf("could not parse kernel version from changelog: %s", firstLine)
	}

	info := &kernelVersionInfo{
		baseVersion:    matches[1], // e.g., "5.4.0-195"
		releaseVersion: matches[2], // eg., "215"
	}
	// eg "5.4.0-195.215"
	info.fullVersion = fmt.Sprintf("%s.%s", info.baseVersion, info.releaseVersion)

	// Extract major version; package naming
	majorVersionRegex := regexp.MustCompile(`([0-9]+\.[0-9]+)\.[0-9]+-[0-9]+`)
	majorMatches := majorVersionRegex.FindStringSubmatch(info.baseVersion)

	if len(majorMatches) >= 2 {
		info.majorVersion = majorMatches[1]
	} else {
		info.majorVersion = info.baseVersion
	}

	return info, nil
}

// createMainKernelPackage creates the main kernel package
func createMainKernelPackage(versionInfo *kernelVersionInfo, snapMetadata pkg.SnapEntry, location file.Location) []pkg.Package {
	kernelPackageName := fmt.Sprintf("linux-image-%s-generic", versionInfo.baseVersion)
	kernelPkg := newDebianPackageFromSnap(
		kernelPackageName,
		versionInfo.fullVersion,
		snapMetadata,
		location,
	)

	return []pkg.Package{kernelPkg}
}

// parseBaseKernelLine extracts base kernel version from a changelog line
func parseBaseKernelLine(line string, majorVersion string, snapMetadata pkg.SnapEntry, location file.Location) *pkg.Package {
	baseKernelRegex := regexp.MustCompile(fmt.Sprintf(`(%s-[0-9]+)\.?[0-9]*`, regexp.QuoteMeta(majorVersion)))
	baseMatches := baseKernelRegex.FindStringSubmatch(line)

	if len(baseMatches) < 2 {
		return nil
	}

	baseKernelVersion := baseMatches[1]
	baseKernelFullRegex := regexp.MustCompile(fmt.Sprintf(`(%s-[0-9]+\.[0-9]+)`, regexp.QuoteMeta(majorVersion)))
	baseFullMatches := baseKernelFullRegex.FindStringSubmatch(line)

	var baseFullVersion string
	if len(baseFullMatches) >= 2 {
		baseFullVersion = baseFullMatches[1]
	} else {
		baseFullVersion = baseKernelVersion
	}

	baseKernelPkg := newDebianPackageFromSnap(
		fmt.Sprintf("linux-image-%s-generic", baseKernelVersion),
		baseFullVersion,
		snapMetadata,
		location,
	)

	return &baseKernelPkg
}
