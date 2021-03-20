package java

import (
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parseJavaArchive

var archiveFormatGlobs = []string{
	"**/*.jar",
	"**/*.war",
	"**/*.ear",
	"**/*.jpi",
	"**/*.hpi",
}

type archiveParser struct {
	discoveredPkgs internal.StringSet
	fileManifest   file.ZipFileManifest
	virtualPath    string
	archivePath    string
	contentPath    string
	fileInfo       archiveFilename
	detectNested   bool
}

// parseJavaArchive is a parser function for java archive contents, returning all Java libraries and nested archives.
func parseJavaArchive(virtualPath string, reader io.Reader) ([]pkg.Package, error) {
	parser, cleanupFn, err := newJavaArchiveParser(virtualPath, reader, true)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, err
	}
	return parser.parse()
}

// uniquePkgKey creates a unique string to identify the given package.
func uniquePkgKey(p *pkg.Package) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", p.Name, p.Version)
}

// newJavaArchiveParser returns a new java archive parser object for the given archive. Can be configured to discover
// and parse nested archives or ignore them.
func newJavaArchiveParser(virtualPath string, reader io.Reader, detectNested bool) (*archiveParser, func(), error) {
	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(reader)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to process java archive: %w", err)
	}

	fileManifest, err := file.NewZipFileManifest(archivePath)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to read files from java archive: %w", err)
	}

	// fetch the last element of the virtual path
	virtualElements := strings.Split(virtualPath, ":")
	currentFilepath := virtualElements[len(virtualElements)-1]

	return &archiveParser{
		discoveredPkgs: internal.NewStringSet(),
		fileManifest:   fileManifest,
		virtualPath:    virtualPath,
		archivePath:    archivePath,
		contentPath:    contentPath,
		fileInfo:       newJavaArchiveFilename(currentFilepath),
		detectNested:   detectNested,
	}, cleanupFn, nil
}

// parse the loaded archive and return all packages found.
func (j *archiveParser) parse() ([]pkg.Package, error) {
	var pkgs = make([]pkg.Package, 0)

	// find the parent package from the java manifest
	parentPkg, err := j.discoverMainPackage()
	if err != nil {
		return nil, fmt.Errorf("could not generate package from %s: %w", j.virtualPath, err)
	}

	// don't add the parent package yet, we still may discover aux info to add to the metadata (but still track it as added to prevent duplicates)
	parentKey := uniquePkgKey(parentPkg)
	if parentKey != "" {
		j.discoveredPkgs.Add(parentKey)
	}

	// find aux packages from pom.properties
	auxPkgs, err := j.discoverPkgsFromPomProperties(parentPkg)
	if err != nil {
		return nil, err
	}
	pkgs = append(pkgs, auxPkgs...)

	// find nested java archive packages
	nestedPkgs, err := j.discoverPkgsFromNestedArchives(parentPkg)
	if err != nil {
		return nil, err
	}
	pkgs = append(pkgs, nestedPkgs...)

	// lastly, add the parent package to the list (assuming the parent exists)
	if parentPkg != nil {
		// only the parent package gets the type, nested packages may be of a different package type (or not of a package type at all, since they may not be bundled)
		parentPkg.Type = j.fileInfo.pkgType()
		pkgs = append([]pkg.Package{*parentPkg}, pkgs...)
	}

	return pkgs, nil
}

// discoverMainPackage parses the root Java manifest used as the parent package to all discovered nested packages.
func (j *archiveParser) discoverMainPackage() (*pkg.Package, error) {
	// search and parse java manifest files
	manifestMatches := j.fileManifest.GlobMatch(manifestGlob)
	if len(manifestMatches) > 1 {
		return nil, fmt.Errorf("found multiple manifests in the jar: %+v", manifestMatches)
	} else if len(manifestMatches) == 0 {
		// we did not find any manifests, but that may not be a problem (there may be other information to generate packages for)
		return nil, nil
	}

	// fetch the manifest file
	contents, err := file.ContentsFromZip(j.archivePath, manifestMatches...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract java manifests (%s): %w", j.virtualPath, err)
	}

	// parse the manifest file into a rich object
	manifestContents := contents[manifestMatches[0]]
	manifest, err := parseJavaManifest(j.archivePath, strings.NewReader(manifestContents))
	if err != nil {
		log.Warnf("failed to parse java manifest (%s): %+v", j.virtualPath, err)
		return nil, nil
	}

	return &pkg.Package{
		Name:         selectName(manifest, j.fileInfo),
		Version:      selectVersion(manifest, j.fileInfo),
		Language:     pkg.Java,
		Type:         pkg.JavaPkg,
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath: j.virtualPath,
			Manifest:    manifest,
		},
	}, nil
}

// discoverPkgsFromPomProperties parses Maven POM properties for a given parent package, returning all listed Java packages found and
// associating each discovered package to the given parent package.
// nolint:funlen,gocognit
func (j *archiveParser) discoverPkgsFromPomProperties(parentPkg *pkg.Package) ([]pkg.Package, error) {
	var pkgs = make([]pkg.Package, 0)
	parentKey := uniquePkgKey(parentPkg)

	// search and parse pom.properties files & fetch the contents
	contents, err := file.ContentsFromZip(j.archivePath, j.fileManifest.GlobMatch(pomPropertiesGlob)...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract pom.properties: %w", err)
	}

	// parse the manifest file into a rich object
	for propsPath, propsContents := range contents {
		propsObj, err := parsePomProperties(propsPath, strings.NewReader(propsContents))
		if err != nil {
			log.Warnf("failed to parse pom.properties (%s): %+v", j.virtualPath, err)
			continue
		}

		if propsObj == nil {
			continue
		}

		if propsObj.Version != "" && propsObj.ArtifactID != "" {
			// TODO: if there is no parentPkg (no java manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package

			// keep the artifact name within the virtual path if this package does not match the parent package
			vPathSuffix := ""
			if parentPkg != nil && !strings.HasPrefix(propsObj.ArtifactID, parentPkg.Name) {
				vPathSuffix += ":" + propsObj.ArtifactID
			}
			virtualPath := j.virtualPath + vPathSuffix

			// discovered props = new package
			p := pkg.Package{
				Name:         propsObj.ArtifactID,
				Version:      propsObj.Version,
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					VirtualPath:   virtualPath,
					PomProperties: propsObj,
					Parent:        parentPkg,
				},
			}

			pkgKey := uniquePkgKey(&p)

			// the name/version pair matches...
			matchesParentPkg := pkgKey == parentKey

			if parentPkg != nil {
				// the virtual path matches...
				matchesParentPkg = matchesParentPkg || parentPkg.Metadata.(pkg.JavaMetadata).VirtualPath == virtualPath

				// the pom artifactId has the parent name or vice versa
				if propsObj.ArtifactID != "" {
					matchesParentPkg = matchesParentPkg || strings.Contains(parentPkg.Name, propsObj.ArtifactID) || strings.Contains(propsObj.ArtifactID, parentPkg.Name)
				}

				if matchesParentPkg {
					// we've run across more information about our parent package, add this info to the parent package metadata
					// the pom properties is typically a better source of information for name and version than the manifest
					if p.Name != parentPkg.Name {
						parentPkg.Name = p.Name
					}
					if p.Version != parentPkg.Version {
						parentPkg.Version = p.Version
					}

					parentMetadata, ok := parentPkg.Metadata.(pkg.JavaMetadata)
					if ok {
						parentMetadata.PomProperties = propsObj
						parentPkg.Metadata = parentMetadata
					}
				}
			}

			if !matchesParentPkg && !j.discoveredPkgs.Contains(pkgKey) {
				// only keep packages we haven't seen yet (and are not related to the parent package)
				pkgs = append(pkgs, p)
			}
		}
	}
	return pkgs, nil
}

// discoverPkgsFromNestedArchives finds Java archives within Java archives, returning all listed Java packages found and
// associating each discovered package to the given parent package.
func (j *archiveParser) discoverPkgsFromNestedArchives(parentPkg *pkg.Package) ([]pkg.Package, error) {
	var pkgs = make([]pkg.Package, 0)

	if !j.detectNested {
		return pkgs, nil
	}

	// search and parse pom.properties files & fetch the contents
	openers, err := file.ExtractFromZipToUniqueTempFile(j.archivePath, j.contentPath, j.fileManifest.GlobMatch(archiveFormatGlobs...)...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract files from zip: %w", err)
	}

	// discover nested artifacts
	for archivePath, archiveOpener := range openers {
		archiveReadCloser, err := archiveOpener.Open()
		if err != nil {
			return nil, fmt.Errorf("unable to open archived file from tempdir: %w", err)
		}
		nestedPath := fmt.Sprintf("%s:%s", j.virtualPath, archivePath)
		nestedPkgs, err := parseJavaArchive(nestedPath, archiveReadCloser)
		if err != nil {
			if closeErr := archiveReadCloser.Close(); closeErr != nil {
				log.Warnf("unable to close archived file from tempdir: %+v", closeErr)
			}
			return nil, fmt.Errorf("unable to process nested java archive (%s): %w", archivePath, err)
		}
		if err = archiveReadCloser.Close(); err != nil {
			return nil, fmt.Errorf("unable to close archived file from tempdir: %w", err)
		}

		// attach the parent package to all discovered packages that are not already associated with a java archive
		for _, p := range nestedPkgs {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
				if metadata.Parent == nil {
					metadata.Parent = parentPkg
				}
				p.Metadata = metadata
			}
			pkgs = append(pkgs, p)
		}
	}

	return pkgs, nil
}
