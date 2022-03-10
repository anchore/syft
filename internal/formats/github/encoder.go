package github

import (
	"fmt"
	"strings"
	"time"

	"github.com/mholt/archiver/v3"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// toGithubModel converts the provided SBOM to a GitHub dependency model
func toGithubModel(s *sbom.SBOM) DependencySnapshot {
	scanTime := time.Now().Format(time.RFC3339) // TODO is there a record of this somewhere?
	v := version.FromBuild().Version
	if v == "[not provided]" {
		v = "0.0.0-dev"
	}
	return DependencySnapshot{
		Version: 0,
		// TODO allow property input to specify the Job, Sha, and Ref
		Detector: DetectorMetadata{
			Name:    internal.ApplicationName,
			URL:     "https://github.com/anchore/syft",
			Version: v,
		},
		Metadata:  toSnapshotMetadata(s),
		Manifests: toGithubManifests(s),
		Scanned:   scanTime,
	}
}

// toSnapshotMetadata captures the linux distribution information and other metadata
func toSnapshotMetadata(s *sbom.SBOM) Metadata {
	out := Metadata{}

	if s.Artifacts.LinuxDistribution != nil {
		d := s.Artifacts.LinuxDistribution
		qualifiers := packageurl.Qualifiers{}
		if len(d.IDLike) > 0 {
			qualifiers = append(qualifiers, packageurl.Qualifier{
				Key:   "like",
				Value: strings.Join(d.IDLike, ","),
			})
		}
		purl := packageurl.NewPackageURL("generic", "", d.ID, d.VersionID, qualifiers, "")
		out["syft:distro"] = purl.ToString()
	}

	return out
}

func filesystem(p pkg.Package) string {
	if len(p.Locations) > 0 {
		return p.Locations[0].FileSystemID
	}
	return ""
}

// isArchive returns true if the path appears to be an archive
func isArchive(path string) bool {
	_, err := archiver.ByExtension(path)
	return err == nil
}

// toPath Generates a string representation of the package location, optionally including the layer hash
func toPath(s source.Metadata, p pkg.Package) string {
	inputPath := strings.TrimPrefix(s.Path, "./")
	if inputPath == "." {
		inputPath = ""
	}
	if len(p.Locations) > 0 {
		location := p.Locations[0]
		packagePath := location.RealPath
		if location.VirtualPath != "" {
			packagePath = location.VirtualPath
		}
		packagePath = strings.TrimPrefix(packagePath, "/")
		switch s.Scheme {
		case source.ImageScheme:
			image := strings.ReplaceAll(s.ImageMetadata.UserInput, ":/", "//")
			return fmt.Sprintf("%s:/%s", image, packagePath)
		case source.FileScheme:
			if isArchive(inputPath) {
				return fmt.Sprintf("%s:/%s", inputPath, packagePath)
			}
			return inputPath
		case source.DirectoryScheme:
			if inputPath != "" {
				return fmt.Sprintf("%s/%s", inputPath, packagePath)
			}
			return packagePath
		}
	}
	return fmt.Sprintf("%s%s", inputPath, s.ImageMetadata.UserInput)
}

// toGithubManifests manifests, each of which represents a specific location that has dependencies
func toGithubManifests(s *sbom.SBOM) Manifests {
	manifests := map[string]*Manifest{}

	for _, p := range s.Artifacts.PackageCatalog.Sorted() {
		path := toPath(s.Source, p)
		manifest, ok := manifests[path]
		if !ok {
			manifest = &Manifest{
				Name: path,
				File: FileInfo{
					SourceLocation: path,
				},
				Resolved: DependencyGraph{},
			}
			fs := filesystem(p)
			if fs != "" {
				manifest.Metadata = Metadata{
					"syft:filesystem": fs,
				}
			}
			manifests[path] = manifest
		}

		name := dependencyName(p)
		manifest.Resolved[name] = DependencyNode{
			Purl:         p.PURL,
			Metadata:     toDependencyMetadata(p),
			Relationship: toDependencyRelationshipType(p),
			Scope:        toDependencyScope(p),
			Dependencies: toDependencies(s, p),
		}
	}

	out := Manifests{}
	for k, v := range manifests {
		out[k] = *v
	}
	return out
}

// dependencyName to make things a little nicer to read; this might end up being lossy
func dependencyName(p pkg.Package) string {
	purl, err := packageurl.FromString(p.PURL)
	if err != nil {
		log.Warnf("Invalid PURL for package: '%s' PURL: '%s' (%w)", p.Name, p.PURL, err)
		return ""
	}
	// don't use qualifiers for this
	purl.Qualifiers = nil
	return purl.ToString()
}

func toDependencyScope(_ pkg.Package) DependencyScope {
	return DependencyScopeRuntime
}

func toDependencyRelationshipType(_ pkg.Package) DependencyRelationship {
	return DependencyRelationshipDirect
}

func toDependencyMetadata(_ pkg.Package) Metadata {
	// We have limited properties: up to 8 with reasonably small values
	// For now, we are encoding the location as part of the key, we are encoding PURLs with most
	// of the other information Grype might need; and the distro information at the top level
	// so we don't need anything here yet
	return Metadata{}
}

func toDependencies(s *sbom.SBOM, p pkg.Package) (out []string) {
	for _, r := range s.Relationships {
		if r.From.ID() == p.ID() {
			if p, ok := r.To.(pkg.Package); ok {
				out = append(out, dependencyName(p))
			}
		}
	}
	return
}
