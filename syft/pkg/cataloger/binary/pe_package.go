package binary

import (
	"path"
	"regexp"
	"sort"
	"strings"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

var (
	// spaceRegex includes nbsp (#160) considered to be a space character
	spaceRegex  = regexp.MustCompile(`[\s\xa0]+`)
	numberRegex = regexp.MustCompile(`\d`)
	// commaSeparatedVersionRegex matches a LEADING comma-separated version run, the form
	// Windows VERSIONINFO resources often carry (mirroring the FILEVERSION x,y,z,w
	// declaration in a .rc file), e.g. "3, 0, 21, 0" on its own or the
	// "1, 0, 0, 1 (WinBuild.160101.0800)" that ships on many Microsoft binaries
	commaSeparatedVersionRegex = regexp.MustCompile(`^\d+(?:\s*,\s*\d+)+`)
)

func newPEPackage(versionResources map[string]string, f file.Location) pkg.Package {
	name := findNameFromVR(versionResources)

	if name == "" {
		// it's possible that the version resources are empty, so we fall back to the file name
		name = strings.TrimSuffix(strings.TrimSuffix(path.Base(f.RealPath), ".exe"), ".dll")
	}

	p := pkg.Package{
		Name:      name,
		Version:   findVersionFromVR(versionResources),
		Locations: file.NewLocationSet(f.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.BinaryPkg,
		Metadata:  newPEBinaryVersionResourcesFromMap(versionResources),
	}

	// If this appears to be Ghostscript, emit a canonical generic purl
	// Example expected: pkg:generic/ghostscript@<version>
	prod := strings.ToLower(spaceNormalize(versionResources["ProductName"]))
	if prod == "" {
		// fall back to FileDescription if ProductName is missing
		prod = strings.ToLower(spaceNormalize(versionResources["FileDescription"]))
	}
	if p.Version != "" && strings.Contains(prod, "ghostscript") {
		// build a generic PURL for ghostscript
		purl := packageurl.NewPackageURL(packageurl.TypeGeneric, "", "ghostscript", p.Version, nil, "").ToString()
		p.PURL = purl
	}

	p.SetID()

	return p
}

func newPEBinaryVersionResourcesFromMap(vr map[string]string) pkg.PEBinary {
	var kvs pkg.KeyValues
	for k, v := range vr {
		if v == "" {
			continue
		}
		kvs = append(kvs, pkg.KeyValue{
			Key:   k,
			Value: spaceNormalize(v),
		})
	}

	sort.Slice(kvs, func(i, j int) bool {
		return kvs[i].Key < kvs[j].Key
	})

	return pkg.PEBinary{
		VersionResources: kvs,
	}
}

func findNameFromVR(versionResources map[string]string) string {
	// PE files not authored by Microsoft tend to use ProductName as an identifier.
	nameFields := []string{"ProductName", "FileDescription", "InternalName", "OriginalFilename"}

	if isMicrosoftVR(versionResources) {
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

	return name
}
func isMicrosoftVR(versionResources map[string]string) bool {
	return strings.Contains(strings.ToLower(versionResources["CompanyName"]), "microsoft") ||
		strings.Contains(strings.ToLower(versionResources["ProductName"]), "microsoft")
}

// spaceNormalize trims and normalizes whitespace in a string.
func spaceNormalize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// ensure valid UTF-8.
	value = strings.ToValidUTF8(value, "")
	// consolidate all whitespace.
	value = spaceRegex.ReplaceAllString(value, " ")
	// remove non-printable characters.
	value = regexp.MustCompile(`[\x00-\x1f]`).ReplaceAllString(value, "")
	// consolidate again and trim.
	value = spaceRegex.ReplaceAllString(value, " ")
	value = strings.TrimSpace(value)
	return value
}

func findVersionFromVR(versionResources map[string]string) string {
	productVersion := extractVersionFromResourcesValue(versionResources["ProductVersion"])
	fileVersion := extractVersionFromResourcesValue(versionResources["FileVersion"])

	if productVersion != "" {
		return productVersion
	}

	return fileVersion
}

func extractVersionFromResourcesValue(version string) string {
	version = strings.TrimSpace(version)
	version = normalizeCommaSeparatedVersion(version)
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

// normalizeCommaSeparatedVersion converts the comma-separated version form used by
// Windows VERSIONINFO resources into the canonical dotted form, e.g. "3, 0, 21, 0"
// becomes "3.0.21.0". Only a leading run of comma-separated numbers is rewritten, and
// whatever follows it is left untouched, so that "1, 0, 0, 1 (WinBuild.160101.0800)"
// becomes "1.0.0.1 (WinBuild.160101.0800)" and is then handled exactly like the dotted
// "10.0.19041.1 (WinBuild.160101.0800)" that reaches this function today. Values that do
// not begin with such a run are returned unchanged.
func normalizeCommaSeparatedVersion(version string) string {
	run := commaSeparatedVersionRegex.FindString(version)
	if run == "" {
		return version
	}

	fields := strings.Split(run, ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}

	return strings.Join(fields, ".") + version[len(run):]
}

func containsNumber(s string) bool {
	return numberRegex.MatchString(s)
}
