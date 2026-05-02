package vscode

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// extensionRecord is the shape of each entry in extensions.json. Only the
// fields we actually surface are decoded; everything else (cache hashes,
// timestamps, install-source URIs, etc.) is intentionally ignored.
type extensionRecord struct {
	Identifier struct {
		ID   string `json:"id"`
		UUID string `json:"uuid"`
	} `json:"identifier"`
	Version  string `json:"version"`
	Metadata struct {
		PublisherDisplayName string `json:"publisherDisplayName"`
		IsBuiltin            bool   `json:"isBuiltin"`
		IsPreReleaseVersion  bool   `json:"isPreReleaseVersion"`
		TargetPlatform       string `json:"targetPlatform"`
	} `json:"metadata"`
}

func parseExtensionsJSON(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var records []extensionRecord
	if err := json.NewDecoder(reader).Decode(&records); err != nil {
		return nil, nil, fmt.Errorf("failed to parse VSCode extensions.json: %w", err)
	}

	var pkgs []pkg.Package
	for _, r := range records {
		publisher, name, ok := splitExtensionID(r.Identifier.ID)
		if !ok || r.Version == "" {
			// malformed entry: missing canonical id or version; skip rather
			// than emit a package without a usable identity.
			continue
		}

		entry := pkg.VscodeExtensionEntry{
			Publisher:            publisher,
			PublisherDisplayName: r.Metadata.PublisherDisplayName,
			UUID:                 r.Identifier.UUID,
			IsBuiltin:            r.Metadata.IsBuiltin,
			IsPreReleaseVersion:  r.Metadata.IsPreReleaseVersion,
		}
		// "undefined" is VSCode's sentinel for cross-platform extensions —
		// treat it as the absence of a target rather than recording a
		// literal "undefined" string.
		if r.Metadata.TargetPlatform != "" && r.Metadata.TargetPlatform != "undefined" {
			entry.TargetPlatform = r.Metadata.TargetPlatform
		}

		p := pkg.Package{
			// Name matches how the extension is referred to on the CLI and in
			// settings.json: "<publisher>.<name>", e.g. "github.copilot-chat".
			Name:      r.Identifier.ID,
			Version:   r.Version,
			Type:      pkg.VscodeExtensionPkg,
			PURL:      packageURL(publisher, name, r.Version),
			Locations: file.NewLocationSet(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Metadata:  entry,
		}
		_ = ctx
		p.SetID()
		pkgs = append(pkgs, p)
	}

	pkg.Sort(pkgs)
	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// splitExtensionID splits an extension id of the form "<publisher>.<name>"
// into its components. Names may contain further dots (e.g. "ms-vscode.cpptools-extension-pack");
// only the first dot delimits publisher from name, per VSCode marketplace conventions.
func splitExtensionID(id string) (publisher, name string, ok bool) {
	if id == "" {
		return "", "", false
	}
	idx := strings.Index(id, ".")
	if idx <= 0 || idx == len(id)-1 {
		return "", "", false
	}
	return id[:idx], id[idx+1:], true
}

// packageURL builds the PURL for a VSCode extension.
//
// There is no formally registered package-url type for VSCode extensions in
// the upstream PURL spec, but "vscode-extension" is the descriptive form
// already used in community SBOM tooling and is what this cataloger emits.
// If the spec adopts a different name in the future the change is local to
// this function and pkg/type.go.
func packageURL(publisher, name, version string) string {
	return packageurl.NewPackageURL(
		"vscode-extension",
		publisher,
		name,
		version,
		nil,
		"",
	).ToString()
}
