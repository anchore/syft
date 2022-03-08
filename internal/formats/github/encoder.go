package github

import (
	"fmt"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/formats/common"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func toGithubModel(s *sbom.SBOM) DependencySnapshot {
	scanTime := time.Now().Format(time.RFC3339) // TODO is there a record of this somewhere?
	versionInfo := version.FromBuild()
	return DependencySnapshot{
		Version: 0,
		// The GitHub specifics must be filled out elsewhere, Syft does not have this information
		//Job: Job{
		//	Name:    "",
		//	ID:      "",
		//	HTMLURL: "",
		//},
		//Sha: "",
		//Ref: "",
		Detector: DetectorMetadata{
			Name:    internal.ApplicationName,
			URL:     "https://github.com/anchore/syft", // TODO is there a good URL to use here?
			Version: versionInfo.Version,
		},
		Metadata:  toSnapshotMetadata(s),
		Manifests: toGithubManifests(s),
		Scanned:   scanTime,
	}
}

var TagFilter = common.RequiredTag("github")

func toSnapshotMetadata(s *sbom.SBOM) Metadata {
	out := Metadata{}

	for k, v := range common.Encode(s.Source, "syft:source", TagFilter) {
		out[k] = v
	}

	for k, v := range common.Encode(s.Descriptor, "syft:descriptor", TagFilter) {
		out[k] = v
	}

	return out
}

func toGithubManifests(s *sbom.SBOM) Manifests {
	path := s.Source.Path
	if path == "" {
		path = s.Source.ImageMetadata.UserInput
	}
	manifest := Manifest{
		Name: path,
		File: FileInfo{
			SourceLocation: fmt.Sprintf("%s/%s", strings.ToLower(strings.TrimSuffix(string(s.Source.Scheme), "Scheme")), path),
		},
		Metadata: Metadata{},
		Resolved: DependencyGraph{},
	}

	for _, p := range s.Artifacts.PackageCatalog.Sorted() {
		purl := shortPURL(p)
		manifest.Resolved[purl] = DependencyNode{
			Purl:         p.PURL,
			Metadata:     toDependencyMetadata(p),
			Relationship: getDependencyRelationshipType(p),
			Scope:        getDependencyScope(p),
			Dependencies: getDependencies(s, p),
		}
	}

	out := Manifests{}
	out[path] = manifest
	return out
}

func shortPURL(p pkg.Package) string {
	purl, err := packageurl.FromString(p.PURL)
	if err != nil {
		log.Warnf("Invalid PURL for package: '%s' PURL: '%s' (%w)", p.Name, p.PURL, err)
		return ""
	}
	// don't use qualifiers for this
	purl.Qualifiers = nil
	return purl.ToString()
}

func getDependencyScope(p pkg.Package) DependencyScope {
	return DependencyScopeRuntime
}

func getDependencyRelationshipType(p pkg.Package) DependencyRelationship {
	return DependencyRelationshipDirect
}

func toDependencyMetadata(p pkg.Package) Metadata {
	out := Metadata{}
	if len(p.Locations) > 0 {
		// We have limited properties, only encode the first location
		out["syft:location"] = p.Locations[0].Coordinates.RealPath
		//for k, v := range common.Encode(p.Locations, "syft:location", TagFilter) {
		//	out[k] = v
		//}
	}
	if p.Metadata != nil {
		props := common.Encode(p.Metadata, "syft:metadata", TagFilter)
		if len(props) > 0 {
			out["syft:metadata:="] = string(p.MetadataType)
			for k, v := range props {
				out[k] = v
			}
		}
	}
	return out
}

func getDependencies(s *sbom.SBOM, p pkg.Package) (out []string) {
	for _, r := range s.Relationships {
		if r.From.ID() == p.ID() {
			if p, ok := r.To.(pkg.Package); ok {
				purl := shortPURL(p)
				out = append(out, purl)
			}
		}
	}
	return
}
