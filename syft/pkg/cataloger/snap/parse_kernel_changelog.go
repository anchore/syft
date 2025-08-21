package snap

import (
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

// parseKernelChangelog parses changelog files from kernel snaps to extract kernel version
func parseKernelChangelog(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// The file should be gzipped
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gzip reader for changelog: %w", err)
	}
	defer gzReader.Close()

	// Read the content
	content, err := readAll(gzReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read changelog content: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) == 0 {
		return nil, nil, fmt.Errorf("changelog file is empty")
	}

	// Parse the first line to extract kernel version information
	// Format: "linux (5.4.0-195.215) focal; urgency=medium"
	firstLine := lines[0]
	
	// Extract kernel version using regex
	kernelVersionRegex := regexp.MustCompile(`linux \(([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)\.([0-9]+)\)`)
	matches := kernelVersionRegex.FindStringSubmatch(firstLine)
	
	if len(matches) < 3 {
		return nil, nil, fmt.Errorf("could not parse kernel version from changelog: %s", firstLine)
	}

	baseVersion := matches[1]     // e.g., "5.4.0-195"
	releaseVersion := matches[2]  // e.g., "215"
	fullVersion := fmt.Sprintf("%s.%s", baseVersion, releaseVersion) // e.g., "5.4.0-195.215"

	// Extract major version for package naming
	majorVersionRegex := regexp.MustCompile(`([0-9]+\.[0-9]+)\.[0-9]+-[0-9]+`)
	majorMatches := majorVersionRegex.FindStringSubmatch(baseVersion)
	
	var majorVersion string
	if len(majorMatches) >= 2 {
		majorVersion = majorMatches[1] // e.g., "5.4"
	} else {
		majorVersion = baseVersion
	}

	snapMetadata := SnapMetadata{
		SnapType: SnapTypeKernel,
	}

	// Create a Linux kernel image package
	kernelPackageName := fmt.Sprintf("linux-image-%s-generic", baseVersion)
	
	kernelPkg := newDebianPackageFromSnap(
		kernelPackageName,
		fullVersion,
		snapMetadata,
		reader.Location,
	)

	var packages []pkg.Package
	packages = append(packages, kernelPkg)

	// Parse additional lines for base kernel entry if present
	// Look for lines containing version information for the base kernel
	baseKernelEntry := fmt.Sprintf("%s/linux:", strings.ReplaceAll(releaseVersion, ";", "/"))
	
	for _, line := range lines {
		if strings.Contains(line, baseKernelEntry) {
			// Extract base kernel version using regex
			baseKernelRegex := regexp.MustCompile(fmt.Sprintf(`(%s-[0-9]+)\.?[0-9]*`, regexp.QuoteMeta(majorVersion)))
			baseMatches := baseKernelRegex.FindStringSubmatch(line)
			
			if len(baseMatches) >= 2 {
				baseKernelVersion := baseMatches[1]
				baseKernelFullRegex := regexp.MustCompile(fmt.Sprintf(`(%s-[0-9]+\.[0-9]+)`, regexp.QuoteMeta(majorVersion)))
				baseFullMatches := baseKernelFullRegex.FindStringSubmatch(line)
				
				var baseFullVersion string
				if len(baseFullMatches) >= 2 {
					baseFullVersion = baseFullMatches[1]
				} else {
					baseFullVersion = baseKernelVersion
				}

				// Add base kernel package
				baseKernelPkg := newDebianPackageFromSnap(
					fmt.Sprintf("linux-image-%s-generic", baseKernelVersion),
					baseFullVersion,
					snapMetadata,
					reader.Location,
				)
				
				packages = append(packages, baseKernelPkg)
			}
			break
		}
	}

	return packages, nil, nil
}