package java

import (
	"fmt"
	"io"
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal"
	"github.com/anchore/imgbom/internal/file"
)

func uniquePkgKey(p *pkg.Package) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", p.Name, p.Version)
}

func parseJar(virtualPath string, reader io.Reader) ([]pkg.Package, error) {
	return parseJavaArchive(virtualPath, reader)
}

func parseWar(virtualPath string, reader io.Reader) ([]pkg.Package, error) {
	return parseJavaArchive(virtualPath, reader)
}

func parseEar(virtualPath string, reader io.Reader) ([]pkg.Package, error) {
	return parseJavaArchive(virtualPath, reader)
}

func parseJpi(virtualPath string, reader io.Reader) ([]pkg.Package, error) {
	return parseJavaArchive(virtualPath, reader)
}

func parseHpi(virtualPath string, reader io.Reader) ([]pkg.Package, error) {
	return parseJavaArchive(virtualPath, reader)
}

func parseJavaArchive(virtualPath string, reader io.Reader) ([]pkg.Package, error) {
	var pkgs = make([]pkg.Package, 0)
	discoveredPkgs := internal.NewStringSet()

	_, archivePath, cleanupFn, err := saveArchiveToTmp(reader)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, fmt.Errorf("unable to process jar: %w", err)
	}

	fileManifest, err := file.ZipFileManifest(archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read files from jar: %w", err)
	}

	// find the parent package from the java manifest
	parentPkg, err := newPackageFromJavaManifest(virtualPath, archivePath, fileManifest)
	if err != nil {
		return nil, fmt.Errorf("could not generate package from %s: %w", virtualPath, err)
	}

	// don't add the parent package yet, we still may discover aux info to add to the metadata (but still track it as added to prevent duplicates)
	parentKey := uniquePkgKey(parentPkg)
	if parentKey != "" {
		discoveredPkgs.Add(parentKey)
	}

	// find aux packages from pom.properties
	auxPkgs, err := newPackagesFromPomProperties(parentPkg, discoveredPkgs, virtualPath, archivePath, fileManifest)
	if err != nil {
		return nil, err
	}
	pkgs = append(pkgs, auxPkgs...)

	// TODO: search for nested jars... but only in ears? or all the time? and remember we need to capture pkg metadata and type appropriately for each

	// lastly, add the parent package to the list (assuming the parent exists)
	if parentPkg != nil {
		// only the parent package gets the type, nested packages may be of a different package type (or not of a package type at all, since they may not be bundled)
		parentPkg.Type = newJavaArchiveFilename(virtualPath).pkgType()
		pkgs = append([]pkg.Package{*parentPkg}, pkgs...)
	}

	return pkgs, nil
}

func newPackagesFromPomProperties(parentPkg *pkg.Package, discoveredPkgs internal.StringSet, virtualPath, archivePath string, fileManifest file.ZipManifest) ([]pkg.Package, error) {
	var pkgs = make([]pkg.Package, 0)
	parentKey := uniquePkgKey(parentPkg)

	// search and parse pom.properties files & fetch the contents
	contents, err := file.ExtractFilesFromZip(archivePath, fileManifest.GlobMatch(pomPropertiesGlob)...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract pom.properties: %w", err)
	}

	// parse the manifest file into a rich object
	for propsPath, propsContents := range contents {
		propsObj, err := parsePomProperties(propsPath, strings.NewReader(propsContents))
		if err != nil {
			return nil, fmt.Errorf("failed to parse pom.properties (%s): %w", virtualPath, err)
		}

		if propsObj != nil {
			if propsObj.Version != "" && propsObj.ArtifactID != "" {
				// TODO: if there is no parentPkg (no java manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package

				// discovered props = new package
				p := pkg.Package{
					Name:     propsObj.ArtifactID,
					Version:  propsObj.Version,
					Language: pkg.Java,
					Metadata: pkg.JavaMetadata{
						PomProperties: propsObj,
						Parent:        parentPkg,
					},
				}

				pkgKey := uniquePkgKey(&p)

				if !discoveredPkgs.Contains(pkgKey) {
					// only keep packages we haven't seen yet
					pkgs = append(pkgs, p)
				} else if pkgKey == parentKey {
					// we've run across more information about our parent package, add this info to the parent package metadata
					parentMetadata, ok := parentPkg.Metadata.(pkg.JavaMetadata)
					if ok {
						parentMetadata.PomProperties = propsObj
						parentPkg.Metadata = parentMetadata
					}
				}
			}
		}
	}
	return pkgs, nil
}
