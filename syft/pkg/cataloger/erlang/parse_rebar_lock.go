package erlang

import (
	"context"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseRebarLock parses a rebar.lock and returns the discovered Elixir packages.
//

func parseRebarLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	doc, err := parseErlang(reader)
	if err != nil {
		return nil, nil, err
	}

	pkgMap := make(map[string]*pkg.Package)

	// rebar.lock structure is:
	// [
	//   ["version", [
	//     [<<"package-name">>, ["version-type", "version"]...
	//   ],
	//   [
	//     [pkg_hash, [
	//       [<<"package-name">>, <<"package-hash">>]
	//     ],
	//     [pkg_hash_ext, [
	//       [<<"package-name">>, <<"package-hash">>]
	//     ]
	//   ]
	// ]

	versions := doc.Get(0)
	deps := versions.Get(1)

	for _, dep := range deps.Slice() {
		name := dep.Get(0).String()
		versionNode := dep.Get(1)
		versionType := versionNode.Get(0).String()
		version := versionNode.Get(2).String()

		// capture git hashes if no version specified
		if versionType == "git" {
			version = versionNode.Get(2).Get(1).String()
		}

		p := newPackageFromRebar(
			pkg.ErlangRebarLockEntry{
				Name:    name,
				Version: version,
			},
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		pkgMap[name] = &p
	}

	hashes := doc.Get(1)
	for _, hashStruct := range hashes.Slice() {
		hashType := hashStruct.Get(0).String()

		for _, hashValue := range hashStruct.Get(1).Slice() {
			name := hashValue.Get(0).String()
			hash := hashValue.Get(1).String()

			sourcePkg := pkgMap[name]
			if sourcePkg == nil {
				log.WithFields("package", name).Warn("unable find source package")
				continue
			}
			metadata, ok := sourcePkg.Metadata.(pkg.ErlangRebarLockEntry)
			if !ok {
				log.WithFields("package", name).Warn("unable to extract rebar.lock metadata to add hash metadata")
				continue
			}

			switch hashType {
			case "pkg_hash":
				metadata.PkgHash = hash
			case "pkg_hash_ext":
				metadata.PkgHashExt = hash
			}
			sourcePkg.Metadata = metadata
		}
	}

	var packages []pkg.Package
	for _, p := range pkgMap {
		p.SetID()
		packages = append(packages, *p)
	}
	return packages, nil, unknown.IfEmptyf(packages, "unable to determine packages")
}

// integrity check
var _ generic.Parser = parseRebarLock
