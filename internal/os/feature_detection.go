package os

import (
	"context"
	"fmt"
	"regexp"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/sbom"
)

func DetectFeatures(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
	builder.(sbomsync.Accessor).WriteToSBOM(func(s *sbom.SBOM) {
		if s.Artifacts.LinuxDistribution == nil {
			return
		}

		err := findRhelFeatures(resolver, s.Artifacts.LinuxDistribution)
		if err != nil {
			log.WithFields("error", err, "release", s.Artifacts.LinuxDistribution).Trace("error searching for extended support")
		}
	})

	return nil
}

func findRhelFeatures(resolver file.Resolver, release *linux.Release) error {
	if release == nil || release.ID != "rhel" {
		return nil
	}
	contentManifestFiles, err := resolver.FilesByGlob("/root/buildinfo/content_manifests/*.json")
	if err != nil {
		return fmt.Errorf("unable to find content manifests: %w", err)
	}
	for _, contentManifestFile := range contentManifestFiles {
		found, err := hasRhelExtendedSupportInContentManifest(resolver, contentManifestFile)
		if err != nil {
			return fmt.Errorf("unable to read content manifest from %s: %w", contentManifestFile.String(), err)
		}
		if found {
			release.ExtendedSupport = true
			break
		}
	}
	return nil
}

func hasRhelExtendedSupportInContentManifest(resolver file.Resolver, contentManifestFile file.Location) (bool, error) {
	contents, err := resolver.FileContentsByLocation(contentManifestFile)
	if err != nil {
		return false, fmt.Errorf("unable to read content manifest from %s: %w", contentManifestFile.String(), err)
	}
	defer internal.CloseAndLogError(contents, "content-manifest")

	patterns := []*regexp.Regexp{regexp.MustCompile(`baseos-eus`), regexp.MustCompile(`baseos-eus|appstream-eus`)}
	return internal.MatchAnyFromReader(contents, patterns...)
}
