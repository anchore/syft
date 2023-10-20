package java

import (
	"crypto"
	"fmt"
	"os"
	"path"
	"strings"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseJavaArchive

var archiveFormatGlobs = []string{
	"**/*.jar",
	"**/*.war",
	"**/*.ear",
	"**/*.par",
	"**/*.sar",
	"**/*.nar",
	"**/*.jpi",
	"**/*.hpi",
	"**/*.lpkg", // Zip-compressed package used to deploy applications
	// (aka plugins) to Liferay Portal server. Those files contains .JAR(s) and a .PROPERTIES file, the latter
	// has information about the application and installation requirements.
	// NOTE(jonasagx): If you would like to test it with lpkg file,
	// use: https://web.liferay.com/marketplace/-/mp/download/25019275/7403
	// LifeRay makes it pretty cumbersome to make a such plugins; their docs are
	// out of date, and they charge for their IDE. If you find an example
	// project that we can build in CI feel free to include it
}

// javaArchiveHashes are all the current hash algorithms used to calculate archive digests
var javaArchiveHashes = []crypto.Hash{
	crypto.SHA1,
}

type archiveParser struct {
	fileManifest intFile.ZipFileManifest
	location     file.Location
	archivePath  string
	contentPath  string
	fileInfo     archiveFilename
	detectNested bool
}

// parseJavaArchive is a parser function for java archive contents, returning all Java libraries and nested archives.
func parseJavaArchive(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	parser, cleanupFn, err := newJavaArchiveParser(reader, true)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}
	return parser.parse()
}

// uniquePkgKey creates a unique string to identify the given package.
func uniquePkgKey(groupID string, p *pkg.Package) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s|%s", groupID, p.Name, p.Version)
}

// newJavaArchiveParser returns a new java archive parser object for the given archive. Can be configured to discover
// and parse nested archives or ignore them.
func newJavaArchiveParser(reader file.LocationReadCloser, detectNested bool) (*archiveParser, func(), error) {
	// fetch the last element of the virtual path
	virtualElements := strings.Split(reader.AccessPath(), ":")
	currentFilepath := virtualElements[len(virtualElements)-1]

	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(currentFilepath, reader)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to process java archive: %w", err)
	}

	fileManifest, err := intFile.NewZipFileManifest(archivePath)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to read files from java archive: %w", err)
	}

	return &archiveParser{
		fileManifest: fileManifest,
		location:     reader.Location,
		archivePath:  archivePath,
		contentPath:  contentPath,
		fileInfo:     newJavaArchiveFilename(currentFilepath),
		detectNested: detectNested,
	}, cleanupFn, nil
}

// parse the loaded archive and return all packages found.
func (j *archiveParser) parse() ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	// find the parent package from the java manifest
	parentPkg, err := j.discoverMainPackage()
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate package from %s: %w", j.location, err)
	}

	// find aux packages from pom.properties/pom.xml and potentially modify the existing parentPkg
	// NOTE: we cannot generate sha1 digests from packages discovered via pom.properties/pom.xml
	auxPkgs, err := j.discoverPkgsFromAllMavenFiles(parentPkg)
	if err != nil {
		return nil, nil, err
	}
	pkgs = append(pkgs, auxPkgs...)

	if j.detectNested {
		// find nested java archive packages
		nestedPkgs, nestedRelationships, err := j.discoverPkgsFromNestedArchives(parentPkg)
		if err != nil {
			return nil, nil, err
		}
		pkgs = append(pkgs, nestedPkgs...)
		relationships = append(relationships, nestedRelationships...)
	}

	// lastly, add the parent package to the list (assuming the parent exists)
	if parentPkg != nil {
		pkgs = append([]pkg.Package{*parentPkg}, pkgs...)
	}

	// add pURLs to all packages found
	// note: since package information may change after initial creation when parsing multiple locations within the
	// jar, we wait until the conclusion of the parsing process before synthesizing pURLs.
	for i := range pkgs {
		p := &pkgs[i]
		if m, ok := p.Metadata.(pkg.JavaMetadata); ok {
			p.PURL = packageURL(p.Name, p.Version, m)
		} else {
			log.WithFields("package", p.String()).Warn("unable to extract java metadata to generate purl")
		}
		p.SetID()
	}

	return pkgs, relationships, nil
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
	contents, err := intFile.ContentsFromZip(j.archivePath, manifestMatches...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract java manifests (%s): %w", j.location, err)
	}

	// parse the manifest file into a rich object
	manifestContents := contents[manifestMatches[0]]
	manifest, err := parseJavaManifest(j.archivePath, strings.NewReader(manifestContents))
	if err != nil {
		log.Warnf("failed to parse java manifest (%s): %+v", j.location, err)
		return nil, nil
	}

	// grab and assign digest for the entire archive
	digests, err := getDigestsFromArchive(j.archivePath)
	if err != nil {
		return nil, err
	}

	licenses, name, version, err := j.parseLicenses(manifest)
	if err != nil {
		return nil, err
	}

	return &pkg.Package{
		// TODO: maybe select name should just have a pom properties in it?
		Name:     name,
		Version:  version,
		Language: pkg.Java,
		Licenses: pkg.NewLicenseSet(licenses...),
		Locations: file.NewLocationSet(
			j.location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type:         j.fileInfo.pkgType(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath:    j.location.AccessPath(),
			Manifest:       manifest,
			ArchiveDigests: digests,
		},
	}, nil
}

func (j *archiveParser) parseLicenses(manifest *pkg.JavaManifest) ([]pkg.License, string, string, error) {
	// we use j.location because we want to associate the license declaration with where we discovered the contents in the manifest
	// TODO: when we support locations of paths within archives we should start passing the specific manifest location object instead of the top jar
	licenses := pkg.NewLicensesFromLocation(j.location, selectLicenses(manifest)...)
	/*
		We should name and version from, in this order:
		1. pom.properties if we find exactly 1
		2. pom.xml if we find exactly 1
		3. manifest
		4. filename
	*/
	name, version, pomLicenses := j.guessMainPackageNameAndVersionFromPomInfo()
	if name == "" {
		name = selectName(manifest, j.fileInfo)
	}
	if version == "" {
		version = selectVersion(manifest, j.fileInfo)
	}
	if len(licenses) == 0 {
		// Today we don't have a way to distinguish between licenses from the manifest and licenses from the pom.xml
		// until the file.Location object can support sub-paths (i.e. paths within archives, recursively; issue https://github.com/anchore/syft/issues/2211).
		// Until then it's less confusing to use the licenses from the pom.xml only if the manifest did not list any.
		licenses = append(licenses, pomLicenses...)
	}

	if len(licenses) == 0 {
		fileLicenses, err := j.getLicenseFromFileInArchive()
		if err != nil {
			return nil, "", "", err
		}
		if fileLicenses != nil {
			licenses = append(licenses, fileLicenses...)
		}
	}

	return licenses, name, version, nil
}

type parsedPomProject struct {
	*pkg.PomProject
	Licenses []pkg.License
}

func (j *archiveParser) guessMainPackageNameAndVersionFromPomInfo() (name, version string, licenses []pkg.License) {
	pomPropertyMatches := j.fileManifest.GlobMatch(pomPropertiesGlob)
	pomMatches := j.fileManifest.GlobMatch(pomXMLGlob)
	var pomPropertiesObject pkg.PomProperties
	var pomProjectObject parsedPomProject
	if len(pomPropertyMatches) == 1 || len(pomMatches) == 1 {
		// we have exactly 1 pom.properties or pom.xml in the archive; assume it represents the
		// package we're scanning if the names seem like a plausible match
		properties, _ := pomPropertiesByParentPath(j.archivePath, j.location, pomPropertyMatches)
		projects, _ := pomProjectByParentPath(j.archivePath, j.location, pomMatches)

		for parentPath, propertiesObj := range properties {
			if artifactIDMatchesFilename(propertiesObj.ArtifactID, j.fileInfo.name) {
				pomPropertiesObject = propertiesObj
				if proj, exists := projects[parentPath]; exists {
					pomProjectObject = proj
				}
			}
		}
	}
	name = pomPropertiesObject.ArtifactID
	if name == "" && pomProjectObject.PomProject != nil {
		name = pomProjectObject.ArtifactID
	}
	version = pomPropertiesObject.Version
	if version == "" && pomProjectObject.PomProject != nil {
		version = pomProjectObject.Version
	}
	return name, version, pomProjectObject.Licenses
}

func artifactIDMatchesFilename(artifactID, fileName string) bool {
	if artifactID == "" || fileName == "" {
		return false
	}
	return strings.HasPrefix(artifactID, fileName) || strings.HasSuffix(fileName, artifactID)
}

// discoverPkgsFromAllMavenFiles parses Maven POM properties/xml for a given
// parent package, returning all listed Java packages found for each pom
// properties discovered and potentially updating the given parentPkg with new
// data.
func (j *archiveParser) discoverPkgsFromAllMavenFiles(parentPkg *pkg.Package) ([]pkg.Package, error) {
	if parentPkg == nil {
		return nil, nil
	}

	var pkgs []pkg.Package

	// pom.properties
	properties, err := pomPropertiesByParentPath(j.archivePath, j.location, j.fileManifest.GlobMatch(pomPropertiesGlob))
	if err != nil {
		return nil, err
	}

	// pom.xml
	projects, err := pomProjectByParentPath(j.archivePath, j.location, j.fileManifest.GlobMatch(pomXMLGlob))
	if err != nil {
		return nil, err
	}

	for parentPath, propertiesObj := range properties {
		var pomProject *parsedPomProject
		if proj, exists := projects[parentPath]; exists {
			pomProject = &proj
		}

		pkgFromPom := newPackageFromMavenData(propertiesObj, pomProject, parentPkg, j.location)
		if pkgFromPom != nil {
			pkgs = append(pkgs, *pkgFromPom)
		}
	}

	return pkgs, nil
}

func getDigestsFromArchive(archivePath string) ([]file.Digest, error) {
	archiveCloser, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open archive path (%s): %w", archivePath, err)
	}
	defer archiveCloser.Close()

	// grab and assign digest for the entire archive
	digests, err := intFile.NewDigestsFromFile(archiveCloser, javaArchiveHashes)
	if err != nil {
		log.Warnf("failed to create digest for file=%q: %+v", archivePath, err)
	}

	return digests, nil
}

func (j *archiveParser) getLicenseFromFileInArchive() ([]pkg.License, error) {
	var fileLicenses []pkg.License
	for _, filename := range licenses.FileNames() {
		licenseMatches := j.fileManifest.GlobMatch("/META-INF/" + filename)
		if len(licenseMatches) == 0 {
			// Try the root directory if it's not in META-INF
			licenseMatches = j.fileManifest.GlobMatch("/" + filename)
		}

		if len(licenseMatches) > 0 {
			contents, err := intFile.ContentsFromZip(j.archivePath, licenseMatches...)
			if err != nil {
				return nil, fmt.Errorf("unable to extract java license (%s): %w", j.location, err)
			}

			for _, licenseMatch := range licenseMatches {
				licenseContents := contents[licenseMatch]
				parsed, err := licenses.Parse(strings.NewReader(licenseContents), j.location)
				if err != nil {
					return nil, err
				}

				if len(parsed) > 0 {
					fileLicenses = append(fileLicenses, parsed...)
				}
			}
		}
	}

	return fileLicenses, nil
}

func (j *archiveParser) discoverPkgsFromNestedArchives(parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	// we know that all java archives are zip formatted files, so we can use the shared zip helper
	return discoverPkgsFromZip(j.location, j.archivePath, j.contentPath, j.fileManifest, parentPkg)
}

// discoverPkgsFromZip finds Java archives within Java archives, returning all listed Java packages found and
// associating each discovered package to the given parent package.
func discoverPkgsFromZip(location file.Location, archivePath, contentPath string, fileManifest intFile.ZipFileManifest, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	// search and parse pom.properties files & fetch the contents
	openers, err := intFile.ExtractFromZipToUniqueTempFile(archivePath, contentPath, fileManifest.GlobMatch(archiveFormatGlobs...)...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract files from zip: %w", err)
	}

	return discoverPkgsFromOpeners(location, openers, parentPkg)
}

// discoverPkgsFromOpeners finds Java archives within the given files and associates them with the given parent package.
func discoverPkgsFromOpeners(location file.Location, openers map[string]intFile.Opener, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	for pathWithinArchive, archiveOpener := range openers {
		nestedPkgs, nestedRelationships, err := discoverPkgsFromOpener(location, pathWithinArchive, archiveOpener)
		if err != nil {
			log.WithFields("location", location.AccessPath()).Warnf("unable to discover java packages from opener: %+v", err)
			continue
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

		relationships = append(relationships, nestedRelationships...)
	}

	return pkgs, relationships, nil
}

// discoverPkgsFromOpener finds Java archives within the given file.
func discoverPkgsFromOpener(location file.Location, pathWithinArchive string, archiveOpener intFile.Opener) ([]pkg.Package, []artifact.Relationship, error) {
	archiveReadCloser, err := archiveOpener.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open archived file from tempdir: %w", err)
	}
	defer func() {
		if closeErr := archiveReadCloser.Close(); closeErr != nil {
			log.Warnf("unable to close archived file from tempdir: %+v", closeErr)
		}
	}()

	nestedPath := fmt.Sprintf("%s:%s", location.AccessPath(), pathWithinArchive)
	nestedLocation := file.NewLocationFromCoordinates(location.Coordinates)
	nestedLocation.VirtualPath = nestedPath
	nestedPkgs, nestedRelationships, err := parseJavaArchive(nil, nil, file.LocationReadCloser{
		Location:   nestedLocation,
		ReadCloser: archiveReadCloser,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to process nested java archive (%s): %w", pathWithinArchive, err)
	}

	return nestedPkgs, nestedRelationships, nil
}

func pomPropertiesByParentPath(archivePath string, location file.Location, extractPaths []string) (map[string]pkg.PomProperties, error) {
	contentsOfMavenPropertiesFiles, err := intFile.ContentsFromZip(archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	propertiesByParentPath := make(map[string]pkg.PomProperties)
	for filePath, fileContents := range contentsOfMavenPropertiesFiles {
		pomProperties, err := parsePomProperties(filePath, strings.NewReader(fileContents))
		if err != nil {
			log.WithFields("contents-path", filePath, "location", location.AccessPath()).Warnf("failed to parse pom.properties: %+v", err)
			continue
		}

		if pomProperties == nil {
			continue
		}

		if pomProperties.Version == "" || pomProperties.ArtifactID == "" {
			// TODO: if there is no parentPkg (no java manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package
			continue
		}

		propertiesByParentPath[path.Dir(filePath)] = *pomProperties
	}

	return propertiesByParentPath, nil
}

func pomProjectByParentPath(archivePath string, location file.Location, extractPaths []string) (map[string]parsedPomProject, error) {
	contentsOfMavenProjectFiles, err := intFile.ContentsFromZip(archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	projectByParentPath := make(map[string]parsedPomProject)
	for filePath, fileContents := range contentsOfMavenProjectFiles {
		// TODO: when we support locations of paths within archives we should start passing the specific pom.xml location object instead of the top jar
		pomProject, err := parsePomXMLProject(filePath, strings.NewReader(fileContents), location)
		if err != nil {
			log.WithFields("contents-path", filePath, "location", location.AccessPath()).Warnf("failed to parse pom.xml: %+v", err)
			continue
		}

		if pomProject == nil {
			continue
		}

		if pomProject.Version == "" || pomProject.ArtifactID == "" {
			// TODO: if there is no parentPkg (no java manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package
			continue
		}

		projectByParentPath[path.Dir(filePath)] = *pomProject
	}
	return projectByParentPath, nil
}

// newPackageFromMavenData processes a single Maven POM properties for a given parent package, returning all listed Java packages found and
// associating each discovered package to the given parent package. Note the pom.xml is optional, the pom.properties is not.
func newPackageFromMavenData(pomProperties pkg.PomProperties, parsedPomProject *parsedPomProject, parentPkg *pkg.Package, location file.Location) *pkg.Package {
	// keep the artifact name within the virtual path if this package does not match the parent package
	vPathSuffix := ""
	groupID := ""
	if parentMetadata, ok := parentPkg.Metadata.(pkg.JavaMetadata); ok {
		groupID = groupIDFromJavaMetadata(parentPkg.Name, parentMetadata)
	}

	parentKey := fmt.Sprintf("%s:%s:%s", groupID, parentPkg.Name, parentPkg.Version)
	// Since we don't have a package yet, it's important to use the same `field: value` association that we used when creating the parent package
	// See below where Name => pomProperties.ArtifactID and Version => pomProperties.Version. We want to check for potentially nested identical
	// packages and create equal virtual paths so they are de duped in the future
	pomProjectKey := fmt.Sprintf("%s:%s:%s", pomProperties.GroupID, pomProperties.ArtifactID, pomProperties.Version)
	if parentKey != pomProjectKey {
		// build a new virtual path suffix for the package that is different from the parent package
		// we want to use the GroupID and ArtifactID here to preserve uniqueness
		// Some packages have the same name but different group IDs (e.g. "org.glassfish.jaxb/jaxb-core", "com.sun.xml.bind/jaxb-core")
		// https://github.com/anchore/syft/issues/1944
		vPathSuffix += ":" + pomProperties.GroupID + ":" + pomProperties.ArtifactID
	}
	virtualPath := location.AccessPath() + vPathSuffix

	var pkgPomProject *pkg.PomProject
	licenses := make([]pkg.License, 0)
	if parsedPomProject != nil {
		pkgPomProject = parsedPomProject.PomProject
		licenses = append(licenses, parsedPomProject.Licenses...)
	}

	p := pkg.Package{
		Name:    pomProperties.ArtifactID,
		Version: pomProperties.Version,
		Locations: file.NewLocationSet(
			location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Licenses:     pkg.NewLicenseSet(licenses...),
		Language:     pkg.Java,
		Type:         pomProperties.PkgTypeIndicated(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath:   virtualPath,
			PomProperties: &pomProperties,
			PomProject:    pkgPomProject,
			Parent:        parentPkg,
		},
	}

	if packageIdentitiesMatch(p, parentPkg) {
		updateParentPackage(p, parentPkg)
		return nil
	}

	return &p
}

func packageIdentitiesMatch(p pkg.Package, parentPkg *pkg.Package) bool {
	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	parentMetadata, parentOk := parentPkg.Metadata.(pkg.JavaMetadata)
	if !ok || !parentOk {
		switch {
		case !ok:
			log.WithFields("package", p.String()).Trace("unable to extract java metadata to check for matching package identity for package: %s", p.Name)
		case !parentOk:
			log.WithFields("package", parentPkg.String()).Trace("unable to extract java metadata to check for matching package identity for package: %s", parentPkg.Name)
		}
		// if we can't extract metadata, we can check for matching identities via the package name
		// this is not ideal, but it's better than nothing - this should not be used if we have Metadata

		return uniquePkgKey("", &p) == uniquePkgKey("", parentPkg)
	}

	// try to determine identity with the metadata
	groupID := groupIDFromJavaMetadata(p.Name, metadata)
	parentGroupID := groupIDFromJavaMetadata(parentPkg.Name, parentMetadata)
	if uniquePkgKey(groupID, &p) == uniquePkgKey(parentGroupID, parentPkg) {
		return true
	}

	// the virtual path matches...
	if parentMetadata.VirtualPath == metadata.VirtualPath {
		return true
	}

	// the pom artifactId is the parent name
	// note: you CANNOT use name-is-subset-of-artifact-id or vice versa --this is too generic. Shaded jars are a good
	// example of this: where the package name is "cloudbees-analytics-segment-driver" and a child is "analytics", but
	// they do not indicate the same package.
	// NOTE: artifactId might not be a good indicator of uniqueness since archives can contain forks with the same name
	// from different groups (e.g. "org.glassfish.jaxb.jaxb-core" and "com.sun.xml.bind.jaxb-core")
	// we will use this check as a last resort
	if metadata.PomProperties != nil {
		if metadata.PomProperties.ArtifactID != "" && parentPkg.Name == metadata.PomProperties.ArtifactID {
			return true
		}
	}
	return false
}

func updateParentPackage(p pkg.Package, parentPkg *pkg.Package) {
	// we've run across more information about our parent package, add this info to the parent package metadata
	// the pom properties is typically a better source of information for name and version than the manifest
	parentPkg.Name = p.Name
	parentPkg.Version = p.Version

	// we may have learned more about the type via data in the pom properties
	parentPkg.Type = p.Type

	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	if !ok {
		return
	}
	pomPropertiesCopy := *metadata.PomProperties

	// keep the pom properties, but don't overwrite existing pom properties
	parentMetadata, ok := parentPkg.Metadata.(pkg.JavaMetadata)
	if ok && parentMetadata.PomProperties == nil {
		parentMetadata.PomProperties = &pomPropertiesCopy
		parentPkg.Metadata = parentMetadata
	}
}
