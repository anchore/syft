package java

import (
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
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
	fileManifest file.ZipFileManifest
	virtualPath  string
	archivePath  string
	contentPath  string
	fileInfo     archiveFilename
	detectNested bool
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
		fileManifest: fileManifest,
		virtualPath:  virtualPath,
		archivePath:  archivePath,
		contentPath:  contentPath,
		fileInfo:     newJavaArchiveFilename(currentFilepath),
		detectNested: detectNested,
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

	// find aux packages from pom.properties and potentially modify the existing parentPkg
	auxPkgs, err := j.discoverPkgsFromAllPomProperties(parentPkg)
	if err != nil {
		return nil, err
	}
	pkgs = append(pkgs, auxPkgs...)

	if j.detectNested {
		// find nested java archive packages
		nestedPkgs, err := j.discoverPkgsFromNestedArchives(parentPkg)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, nestedPkgs...)
	}

	// lastly, add the parent package to the list (assuming the parent exists)
	if parentPkg != nil {
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
		Type:         j.fileInfo.pkgType(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath: j.virtualPath,
			Manifest:    manifest,
		},
	}, nil
}

// discoverPkgsFromAllPomProperties parses Maven POM properties for a given
// parent package, returning all listed Java packages found for each pom
// properties discovered and potentially updating the given parentPkg with new
// data.
func (j *archiveParser) discoverPkgsFromAllPomProperties(parentPkg *pkg.Package) ([]pkg.Package, error) {
	if parentPkg == nil {
		return nil, nil
	}

	var pkgs []pkg.Package

	// search and parse pom.properties files & fetch the contents
	contentsOfPomPropertiesFiles, err := file.ContentsFromZip(j.archivePath, j.fileManifest.GlobMatch(pomPropertiesGlob)...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract pom.properties: %w", err)
	}

	for filePath, fileContents := range contentsOfPomPropertiesFiles {
		// parse the pom properties file into a rich object
		pomProperties, err := parsePomProperties(filePath, strings.NewReader(fileContents))
		if err != nil {
			log.Warnf("failed to parse pom.properties (%s): %+v", j.virtualPath, err)
			continue
		}

		if pomProperties == nil {
			continue
		}

		if pomProperties.Version == "" || pomProperties.ArtifactID == "" {
			// TODO: if there is no parentPkg (no java manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package
			continue
		}

		pkgs = append(pkgs, j.packagesFromPomProperties(*pomProperties, parentPkg)...)
	}
	return pkgs, nil
}

// packagesFromPomProperties processes a single Maven POM properties for a given parent package, returning all listed Java packages found and
// associating each discovered package to the given parent package.
func (j *archiveParser) packagesFromPomProperties(pomProperties pkg.PomProperties, parentPkg *pkg.Package) []pkg.Package {
	// keep the artifact name within the virtual path if this package does not match the parent package
	vPathSuffix := ""
	if !strings.HasPrefix(pomProperties.ArtifactID, parentPkg.Name) {
		vPathSuffix += ":" + pomProperties.ArtifactID
	}
	virtualPath := j.virtualPath + vPathSuffix

	// discovered props = new package
	p := pkg.Package{
		Name:         pomProperties.ArtifactID,
		Version:      pomProperties.Version,
		Language:     pkg.Java,
		Type:         pomProperties.PkgTypeIndicated(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath:   virtualPath,
			PomProperties: &pomProperties,
			Parent:        parentPkg,
		},
	}

	pkgKey := uniquePkgKey(&p)
	parentKey := uniquePkgKey(parentPkg)

	// the name/version pair matches...
	matchesParentPkg := pkgKey == parentKey

	// the virtual path matches...
	matchesParentPkg = matchesParentPkg || parentPkg.Metadata.(pkg.JavaMetadata).VirtualPath == virtualPath

	// the pom artifactId has the parent name or vice versa
	if pomProperties.ArtifactID != "" {
		matchesParentPkg = matchesParentPkg || strings.Contains(parentPkg.Name, pomProperties.ArtifactID) || strings.Contains(pomProperties.ArtifactID, parentPkg.Name)
	}

	if !matchesParentPkg {
		// only keep packages we haven't seen yet (and are not related to the parent package)
		return []pkg.Package{p}
	}

	// we've run across more information about our parent package, add this info to the parent package metadata
	// the pom properties is typically a better source of information for name and version than the manifest
	if parentPkg.Name == "" {
		parentPkg.Name = p.Name
	}
	if parentPkg.Version == "" {
		parentPkg.Version = p.Version
	}

	// We may have learned more about the type via data in the pom properties
	parentPkg.Type = p.Type

	// keep the pom properties, but don't overwrite existing pom properties
	parentMetadata, ok := parentPkg.Metadata.(pkg.JavaMetadata)
	if ok && parentMetadata.PomProperties == nil {
		parentMetadata.PomProperties = &pomProperties
		parentPkg.Metadata = parentMetadata
	}

	return nil
}

// discoverPkgsFromNestedArchives finds Java archives within Java archives, returning all listed Java packages found and
// associating each discovered package to the given parent package.
func (j *archiveParser) discoverPkgsFromNestedArchives(parentPkg *pkg.Package) ([]pkg.Package, error) {
	var pkgs = make([]pkg.Package, 0)

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
