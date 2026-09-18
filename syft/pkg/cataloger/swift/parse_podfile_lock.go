package swift

import (
	"context"
	"fmt"
	"sort"
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
	Pods            []any                     `yaml:"PODS"`
	Dependencies    []string                  `yaml:"DEPENDENCIES"`
	SpecRepos       map[string][]string       `yaml:"SPEC REPOS"`
	SpecChecksums   map[string]string         `yaml:"SPEC CHECKSUMS"`
	ExternalSources map[string]map[string]any `yaml:"EXTERNAL SOURCES"`
	PodfileChecksum string                    `yaml:"PODFILE CHECKSUM"`
	Cocopods        string                    `yaml:"COCOAPODS"`
}

// externalSource is how a pod is resolved when it does not come from a spec
// repo. CocoaPods records this in the "EXTERNAL SOURCES" section with Ruby
// symbol keys, e.g.
//
//	EXTERNAL SOURCES:
//	  Flutter:
//	    :path: Flutter
//
// The distinction matters to consumers of the SBOM. A `:path:` pod is built
// from a podspec in the working tree, so its version is whatever generated that
// podspec rather than a published release — Flutter's tooling, for instance,
// hardcodes `s.version = '1.0.0'` when generating the Flutter pod's podspec, so
// every Flutter iOS project reports `Flutter (1.0.0)` whatever SDK is
// installed. A `:git:` pod, by contrast, names a real upstream revision.
type externalSource struct {
	Kind     string
	Location string
}

// externalSourceFor returns how the named pod is resolved, if the lockfile says
// it comes from outside a spec repo. Subspecs inherit from their root pod:
// "Flutter/Core" is resolved by the "Flutter" entry.
func (psl *podfileLock) externalSourceFor(podName string) externalSource {
	if len(psl.ExternalSources) == 0 {
		return externalSource{}
	}

	entry, found := psl.ExternalSources[strings.Split(podName, "/")[0]]
	if !found {
		return externalSource{}
	}

	// Sorted so the result does not depend on map iteration order when a pod
	// declares several keys (`:git:` alongside `:tag:`, say).
	keys := make([]string, 0, len(entry))
	for key := range entry {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		kind := strings.TrimPrefix(key, ":")
		switch kind {
		case "path", "git", "podspec":
			location, _ := entry[key].(string)
			return externalSource{Kind: kind, Location: location}
		}
	}

	return externalSource{}
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
		splits := strings.Split(podBlob, " ")
		podName := splits[0]
		podVersion := strings.TrimSuffix(strings.TrimPrefix(splits[1], "("), ")")
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
				podfile.externalSourceFor(podName),
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
