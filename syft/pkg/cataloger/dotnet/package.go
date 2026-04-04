package dotnet

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/go-version"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

var (
	// spaceRegex includes nbsp (#160) considered to be a space character
	spaceRegex              = regexp.MustCompile(`[\s\xa0]+`)
	numberRegex             = regexp.MustCompile(`\d`)
	versionPunctuationRegex = regexp.MustCompile(`[.,]+`)
)

type runtimeFamily string

const (
	unknownRuntimeFamily    runtimeFamily = ""
	netRuntimeFamily        runtimeFamily = "net"
	aspNetCoreRuntimeFamily runtimeFamily = "aspnet_core"
)

// newDotnetDepsPackage creates a new Dotnet dependency package from a logicalDepsJSONPackage.
// Note that the new logicalDepsJSONPackage now directly holds library and executable information.
func newDotnetDepsPackage(lp logicalDepsJSONPackage, depsLocation file.Location) *pkg.Package {
	name, ver := extractNameAndVersion(lp.NameVersion)
	locs := file.NewLocationSet(depsLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	for _, pe := range lp.Executables {
		locs.Add(pe.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}

	m := newDotnetDepsEntry(lp)

	var cpes []cpe.CPE
	if isRuntime(name) {
		cpes = runtimeCPEs(name, ver)
	}

	p := &pkg.Package{
		Name:      name,
		Version:   ver,
		Locations: locs,
		PURL:      packageURL(m),
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		CPEs:      cpes,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func isRuntime(name string) bool {
	return runtimeFamilyFromName(name) != unknownRuntimeFamily
}


func runtimeFamilyFromName(name string) runtimeFamily {
	normalizedName := strings.ToLower(name)

	// found in self-contained or framework-dependent apps in deps.json entries
	if strings.HasPrefix(normalizedName, "runtimepack.microsoft.aspnetcore.app.runtime") ||
		strings.HasPrefix(normalizedName, "microsoft.aspnetcore.app.runtime") ||
		normalizedName == "microsoft.aspnetcore.app" ||
		(strings.HasPrefix(normalizedName, "runtime") && strings.HasSuffix(normalizedName, "microsoft.aspnetcore.app")) {
		return aspNetCoreRuntimeFamily
	}

	// found in self-contained, framework-dependent, and synthesized runtime packages
	if strings.HasPrefix(normalizedName, "runtimepack.microsoft.netcore.app.runtime") ||
		strings.HasPrefix(normalizedName, "microsoft.netcore.app.runtime") ||
		normalizedName == "microsoft.netcore.app" ||
		(strings.HasPrefix(normalizedName, "runtime") && strings.HasSuffix(normalizedName, "microsoft.netcore.app")) {
		return netRuntimeFamily
	}

	return unknownRuntimeFamily
}

func runtimeCPEs(name, ver string) []cpe.CPE {
	family := runtimeFamilyFromName(name)
	if family == unknownRuntimeFamily {
		return nil
	}

	fields := strings.Split(ver, ".")
	if len(fields) == 0 {
		return nil
	}

	normalizedVersionFields := make([]string, 0, len(fields))
	majorVersion, err := strconv.Atoi(fields[0])
	if err != nil {
		log.WithFields("error", err).Tracef("failed to parse .NET runtime major version from %q", ver)
		return nil
	}
	normalizedVersionFields = append(normalizedVersionFields, strconv.Itoa(majorVersion))

	for _, field := range fields[1:] {
		value, err := strconv.Atoi(field)
		if err != nil {
			log.WithFields("error", err).Tracef("failed to parse .NET runtime version component %q from %q", field, ver)
			return nil
		}
		normalizedVersionFields = append(normalizedVersionFields, strconv.Itoa(value))
	}

	if len(normalizedVersionFields) == 1 {
		normalizedVersionFields = append(normalizedVersionFields, "0")
	}

	productName := ".net"
	if family == aspNetCoreRuntimeFamily {
		productName = "asp.net_core"
	} else if majorVersion < 5 {
		productName = ".net_core"
	}

	return []cpe.CPE{
		{
			Attributes: cpe.Attributes{
				Part:    "a",
				Vendor:  "microsoft",
				Product: productName,
				Version: strings.Join(normalizedVersionFields, "."),
			},
			// we didn't find this in the underlying material, but this is the convention in NVD and we are certain this is a runtime package
			Source: cpe.DeclaredSource,
		},
	}
}

// newDotnetDepsEntry creates a Dotnet dependency entry using the new logicalDepsJSONPackage.
func newDotnetDepsEntry(lp logicalDepsJSONPackage) pkg.DotnetDepsEntry {
	name, ver := extractNameAndVersion(lp.NameVersion)

	// since this is a metadata type, we should not allocate this collection unless there are entries; otherwise
	// the JSON serialization will produce an empty object instead of omitting the field.
	var pes map[string]pkg.DotnetPortableExecutableEntry
	if len(lp.Executables) > 0 {
		pes = make(map[string]pkg.DotnetPortableExecutableEntry)
		for _, pe := range lp.Executables {
			pes[pe.TargetPath] = newDotnetPortableExecutableEntry(pe)
		}
	}

	var path, sha, hashPath, libType string
	lib := lp.Library
	if lib != nil {
		path = lib.Path
		sha = lib.Sha512
		hashPath = lib.HashPath
		libType = lib.Type
	}

	return pkg.DotnetDepsEntry{
		Name:        name,
		Version:     ver,
		Path:        path,
		Sha512:      sha,
		HashPath:    hashPath,
		Type:        libType,
		Executables: pes,
	}
}

// newDotnetPortableExecutableEntry creates a portable executable entry from a File.
func newDotnetPortableExecutableEntry(pe logicalPE) pkg.DotnetPortableExecutableEntry {
	return newDotnetPortableExecutableEntryFromMap(pe.VersionResources)
}

func newDotnetPortableExecutableEntryFromMap(vr map[string]string) pkg.DotnetPortableExecutableEntry {
	return pkg.DotnetPortableExecutableEntry{
		// for some reason, the assembly version is sometimes stored as "Assembly Version" and sometimes as "AssemblyVersion"
		AssemblyVersion: cleanVersionResourceField(vr["Assembly Version"], vr["AssemblyVersion"]),
		LegalCopyright:  cleanVersionResourceField(vr["LegalCopyright"]),
		Comments:        cleanVersionResourceField(vr["Comments"]),
		InternalName:    cleanVersionResourceField(vr["InternalName"]),
		CompanyName:     cleanVersionResourceField(vr["CompanyName"]),
		ProductName:     cleanVersionResourceField(vr["ProductName"]),
		ProductVersion:  cleanVersionResourceField(vr["ProductVersion"]),
	}
}

func cleanVersionResourceField(values ...string) string {
	for _, value := range values {
		if value == "" {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}

func getDepsJSONFilePrefix(p string) string {
	r := regexp.MustCompile(`([^\\\/]+)\.deps\.json$`)
	match := r.FindStringSubmatch(p)
	if len(match) > 1 {
		return match[1]
	}

	r = regexp.MustCompile(`([^\\\/]+)\.exe$`)
	match = r.FindStringSubmatch(p)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func extractNameAndVersion(nameVersion string) (name, version string) {
	fields := strings.Split(nameVersion, "/")
	name = fields[0]
	if len(fields) > 1 {
		version = fields[1]
	}
	return
}

func createNameAndVersion(name, version string) string {
	return fmt.Sprintf("%s/%s", name, version)
}

func packageURL(m pkg.DotnetDepsEntry) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		// Although we use TypeNuget here due to historical reasons, note that it does not necessarily
		// mean the package is a NuGet package.
		packageurl.TypeNuget,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}

func newDotnetBinaryPackage(versionResources map[string]string, f file.Location) pkg.Package {
	// TODO: we may decide to use the runtime information in the metadata, but that is not captured today
	name, _ := findNameAndRuntimeFromVersionResources(versionResources)

	if name == "" {
		// older .NET runtime dlls may not have any version resources
		name = strings.TrimSuffix(strings.TrimSuffix(path.Base(f.RealPath), ".exe"), ".dll")
	}

	ver := findVersionFromVersionResources(versionResources)

	metadata := newDotnetPortableExecutableEntryFromMap(versionResources)

	p := pkg.Package{
		Name:      name,
		Version:   ver,
		Locations: file.NewLocationSet(f.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.DotnetPkg,
		Language:  pkg.Dotnet,
		PURL:      binaryPackageURL(name, ver),
		Metadata:  metadata,
	}

	p.SetID()

	return p
}

func binaryPackageURL(name, version string) string {
	if name == "" {
		return ""
	}
	return packageurl.NewPackageURL(
		packageurl.TypeNuget,
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}

var binRuntimeSuffixPattern = regexp.MustCompile(`\s*\((?P<runtime>net[^)]*[0-9]+(\.[0-9]+)?)\)$`)

func findNameAndRuntimeFromVersionResources(versionResources map[string]string) (string, string) {
	// PE files not authored by Microsoft tend to use ProductName as an identifier.
	nameFields := []string{"ProductName", "FileDescription", "InternalName", "OriginalFilename"}

	if isMicrosoftVersionResource(versionResources) {
		// for Microsoft files, prioritize FileDescription.
		nameFields = []string{"FileDescription", "InternalName", "OriginalFilename", "ProductName"}
	}

	var name string
	for _, field := range nameFields {
		value := spaceNormalize(versionResources[field])
		if value == "" {
			continue
		}
		name = value
		break
	}

	var runtime string
	// look for indications of the runtime, such as "(net8.0)" or "(netstandard2.2)" suffixes
	runtimes := binRuntimeSuffixPattern.FindStringSubmatch(name)
	if len(runtimes) > 1 {
		runtime = strings.TrimSpace(runtimes[1])
		name = strings.TrimSpace(strings.TrimSuffix(name, runtimes[0]))
	}

	return name, runtime
}
func isMicrosoftVersionResource(versionResources map[string]string) bool {
	return strings.Contains(strings.ToLower(versionResources["CompanyName"]), "microsoft") ||
		strings.Contains(strings.ToLower(versionResources["ProductName"]), "microsoft")
}

// spaceNormalize trims and normalizes whitespace in a string.
func spaceNormalize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// Ensure valid UTF-8.
	value = strings.ToValidUTF8(value, "")
	// Consolidate all whitespace.
	value = spaceRegex.ReplaceAllString(value, " ")
	// Remove non-printable characters.
	value = regexp.MustCompile(`[\x00-\x1f]`).ReplaceAllString(value, "")
	// Consolidate again and trim.
	value = spaceRegex.ReplaceAllString(value, " ")
	value = strings.TrimSpace(value)
	return value
}

func findVersionFromVersionResources(versionResources map[string]string) string {
	productVersion := extractVersionFromResourcesValue(versionResources["ProductVersion"])
	fileVersion := extractVersionFromResourcesValue(versionResources["FileVersion"])

	semanticVersionCompareResult := keepGreaterSemanticVersion(productVersion, fileVersion)
	if semanticVersionCompareResult != "" {
		return semanticVersionCompareResult
	}

	productVersionDetail := punctuationCount(productVersion)
	fileVersionDetail := punctuationCount(fileVersion)

	if containsNumber(productVersion) && productVersionDetail >= fileVersionDetail {
		return productVersion
	}
	if containsNumber(fileVersion) && fileVersionDetail > 0 {
		return fileVersion
	}
	if containsNumber(productVersion) {
		return productVersion
	}
	if containsNumber(fileVersion) {
		return fileVersion
	}

	return productVersion
}

func extractVersionFromResourcesValue(version string) string {
	version = strings.TrimSpace(version)
	out := ""
	for i, f := range strings.Fields(version) {
		if containsNumber(out) && !containsNumber(f) {
			return out
		}
		if i == 0 {
			out = f
		} else {
			out += " " + f
		}
	}
	return out
}

func keepGreaterSemanticVersion(productVersion string, fileVersion string) string {
	semanticProductVersion, err := version.NewVersion(productVersion)
	if err != nil || semanticProductVersion == nil {
		log.Tracef("Unable to create semantic version from product version %s", productVersion)
		return ""
	}

	semanticFileVersion, err := version.NewVersion(fileVersion)
	if err != nil || semanticFileVersion == nil {
		log.Tracef("Unable to create semantic version from file version %s", fileVersion)
		return productVersion
	}

	if semanticProductVersion.Equal(semanticFileVersion) {
		return ""
	}
	if semanticFileVersion.GreaterThan(semanticProductVersion) {
		return fileVersion
	}
	return productVersion
}

func containsNumber(s string) bool {
	return numberRegex.MatchString(s)
}

func punctuationCount(s string) int {
	return len(versionPunctuationRegex.FindAllString(s, -1))
}
