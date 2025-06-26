package model

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/mholt/archives"
)

// ToGithubModel converts the provided SBOM to a GitHub dependency model
func ToGithubModel(s *sbom.SBOM) DependencySnapshot {
	scanTime := time.Now().Format(time.RFC3339) // TODO is there a record of this somewhere?
	v := s.Descriptor.Version
	if v == "[not provided]" || v == "" {
		v = "0.0.0-dev"
	}
	return DependencySnapshot{
		Version: 0,
		// TODO allow property input to specify the Job, Sha, and Ref
		Detector: DetectorMetadata{
			Name:    s.Descriptor.Name,
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
	locations := p.Locations.ToSlice()
	if len(locations) > 0 {
		return locations[0].FileSystemID
	}
	return ""
}

// toGithubManifests manifests, each of which represents a specific location that has dependencies
func toGithubManifests(s *sbom.SBOM) Manifests {
	manifests := map[string]*Manifest{}

	for _, p := range s.Artifacts.Packages.Sorted() {
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
			PackageURL:   p.PURL,
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

// toPath Generates a string representation of the package location, optionally including the layer hash
func toPath(s source.Description, p pkg.Package) string {
	inputPath := trimRelative(s.Name)
	locations := p.Locations.ToSlice()
	if len(locations) > 0 {
		location := locations[0]
		packagePath := location.RealPath
		if location.AccessPath != "" {
			packagePath = location.AccessPath
		}
		packagePath = strings.TrimPrefix(packagePath, "/")
		switch metadata := s.Metadata.(type) {
		case source.ImageMetadata:
			image := strings.ReplaceAll(metadata.UserInput, ":/", "//")
			return fmt.Sprintf("%s:/%s", image, packagePath)
		case source.FileMetadata:
			path := trimRelative(metadata.Path)
			if isArchive(metadata.Path) {
				return fmt.Sprintf("%s:/%s", path, packagePath)
			}
			return path
		case source.DirectoryMetadata:
			path := trimRelative(metadata.Path)
			if path != "" {
				return fmt.Sprintf("%s/%s", path, packagePath)
			}
			return packagePath
		}
	}
	return inputPath
}

func trimRelative(s string) string {
	s = strings.TrimPrefix(s, "./")
	if s == "." {
		s = ""
	}
	return s
}

// isArchive returns true if the path appears to be an archive
func isArchive(path string) bool {
	format, _, err := archives.Identify(context.Background(), path, nil)
	return err == nil && format != nil
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

// dependencyName to make things a little nicer to read; this might end up being lossy
func dependencyName(p pkg.Package) string {
	purl, err := packageurl.FromString(p.PURL)
	if err != nil {
		log.Debugf("Invalid PURL for package: '%s' PURL: '%s' (%w)", p.Name, p.PURL, err)
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
