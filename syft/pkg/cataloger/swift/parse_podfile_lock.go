package swift

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parsePodfileLock

type podfileLock struct {
	Pods            []any               `yaml:"PODS"`
	Dependencies    []string            `yaml:"DEPENDENCIES"`
	SpecRepos       map[string][]string `yaml:"SPEC REPOS"`
	SpecChecksums   map[string]string   `yaml:"SPEC CHECKSUMS"`
	PodfileChecksum string              `yaml:"PODFILE CHECKSUM"`
	Cocopods        string              `yaml:"COCOAPODS"`
}

// parsePodfileLock is a parser function for Podfile.lock contents, returning all cocoapods pods discovered.
func parsePodfileLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var podfile podfileLock
	if err := yaml.NewDecoder(reader).Decode(&podfile); err != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml: %w", err)
	}

	var pkgs []pkg.Package
	for _, podInterface := range podfile.Pods {
		var podBlob string
		switch v := podInterface.(type) {
		case map[string]any:
			for k := range v {
				podBlob = k
			}
		case string:
			podBlob = v
		default:
			return nil, nil, fmt.Errorf("malformed podfile.lock")
		}
		podName, podVersion, ok := strings.Cut(podBlob, " ")
		if !ok {
			return nil, nil, errors.New("malformed podfile.lock: pod has no version")
		}
		podVersion = strings.TrimSuffix(strings.TrimPrefix(podVersion, "("), ")")
		podRootPkg := strings.Split(podName, "/")[0]

		var pkgHash string
		pkgHash, exists := podfile.SpecChecksums[podRootPkg]
		if !exists {
			return nil, nil, fmt.Errorf("malformed podfile.lock: incomplete checksums")
		}

		pkgs = append(
			pkgs,
			newCocoaPodsPackage(
				podName,
				podVersion,
				pkgHash,
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
