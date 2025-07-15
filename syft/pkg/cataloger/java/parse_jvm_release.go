package java

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/packageurl-go"
	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	// this is a very permissive glob that will match more than just the JVM release file.
	// we started with "**/{java,jvm}/*/release", but this prevents scanning JVM archive contents (e.g. jdk8u402.zip).
	// this approach lets us check more files for JVM release info, but be rather silent about errors.
	jvmReleaseGlob = "**/release"
	oracleVendor   = "oracle"
	openJdkProduct = "openjdk"
	jre            = "jre"
	jdk            = "jdk"
)

// the /opt/java/openjdk/release file (and similar paths) is a file that is present in the multiple OpenJDK distributions
// here's an example of the contents of the file:
//
// IMPLEMENTOR="Eclipse Adoptium"
// IMPLEMENTOR_VERSION="Temurin-21.0.4+7"
// JAVA_RUNTIME_VERSION="21.0.4+7-LTS"
// JAVA_VERSION="21.0.4"
// JAVA_VERSION_DATE="2024-07-16"
// LIBC="gnu"
// MODULES="java.base java.compiler java.datatransfer java.xml java.prefs java.desktop java.instrument java.logging java.management java.security.sasl java.naming java.rmi java.management.rmi java.net.http java.scripting java.security.jgss java.transaction.xa java.sql java.sql.rowset java.xml.crypto java.se java.smartcardio jdk.accessibility jdk.internal.jvmstat jdk.attach jdk.charsets jdk.internal.opt jdk.zipfs jdk.compiler jdk.crypto.ec jdk.crypto.cryptoki jdk.dynalink jdk.internal.ed jdk.editpad jdk.hotspot.agent jdk.httpserver jdk.incubator.vector jdk.internal.le jdk.internal.vm.ci jdk.internal.vm.compiler jdk.internal.vm.compiler.management jdk.jartool jdk.javadoc jdk.jcmd jdk.management jdk.management.agent jdk.jconsole jdk.jdeps jdk.jdwp.agent jdk.jdi jdk.jfr jdk.jlink jdk.jpackage jdk.jshell jdk.jsobject jdk.jstatd jdk.localedata jdk.management.jfr jdk.naming.dns jdk.naming.rmi jdk.net jdk.nio.mapmode jdk.random jdk.sctp jdk.security.auth jdk.security.jgss jdk.unsupported jdk.unsupported.desktop jdk.xml.dom"
// OS_ARCH="aarch64"
// OS_NAME="Linux"
// SOURCE=".:git:13710926b798"
// BUILD_SOURCE="git:1271f10a26c47e1489a814dd2731f936a588d621"
// BUILD_SOURCE_REPO="https://github.com/adoptium/temurin-build.git"
// SOURCE_REPO="https://github.com/adoptium/jdk21u.git"
// FULL_VERSION="21.0.4+7-LTS"
// SEMANTIC_VERSION="21.0.4+7"
// BUILD_INFO="OS: Linux Version: 5.4.0-150-generic"
// JVM_VARIANT="Hotspot"
// JVM_VERSION="21.0.4+7-LTS"
// IMAGE_TYPE="JDK"
//
// In terms of the temurin flavor, these are controlled by:
// - config: https://github.com/adoptium/temurin-build/blob/v2023.01.03/sbin/common/config_init.sh
// - build script: https://github.com/adoptium/temurin-build/blob/v2023.01.03/sbin/build.sh#L1584-L1796

type jvmCpeInfo struct {
	vendor, product, version string
}

func parseJVMRelease(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	ri, err := parseJvmReleaseInfo(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse JVM release info %q: %w", reader.Path(), err)
	}

	if ri == nil {
		// TODO: known-unknown: expected JDK installation package
		return nil, nil, nil
	}

	version := jvmPackageVersion(ri)
	// TODO: detect old and new version format from multiple fields

	licenses := jvmLicenses(resolver, ri)

	locations := file.NewLocationSet(reader.Location)

	for _, lic := range licenses.ToSlice() {
		locations.Add(lic.Locations.ToSlice()...)
	}

	installDir := path.Dir(reader.Path())
	files, hasJdk := findJvmFiles(resolver, installDir)

	// the reason we use the reference to get the real path is in cases where the file cataloger is involved
	// (thus the real path is not available except for in the original file reference). This is important
	// since the path is critical for distinguishing between different JVM vendors.
	vendor, product := jvmPrimaryVendorProduct(ri.Implementor, string(reader.Reference().RealPath), ri.ImageType, hasJdk)

	p := pkg.Package{
		Name:      product,
		Locations: locations,
		Version:   version,
		CPEs:      jvmCpes(version, vendor, product, ri.ImageType, hasJdk),
		PURL:      jvmPurl(*ri, version, vendor, product),
		Licenses:  licenses,
		Type:      pkg.BinaryPkg,
		Metadata: pkg.JavaVMInstallation{
			Release: *ri,
			Files:   files,
		},
	}
	p.SetID()

	return []pkg.Package{p}, nil, nil
}

func jvmLicenses(_ file.Resolver, _ *pkg.JavaVMRelease) pkg.LicenseSet {
	// TODO: get this from the dir(<RELEASE>)/legal/**/LICENSE files when we start cataloging license content
	// see https://github.com/anchore/syft/issues/656
	return pkg.NewLicenseSet()
}

func findJvmFiles(resolver file.Resolver, installDir string) ([]string, bool) {
	ownedLocations, err := resolver.FilesByGlob(installDir + "/**")
	if err != nil {
		// TODO: known-unknowns
		log.WithFields("path", installDir, "error", err).Trace("unable to find installed JVM files")
	}

	var results []string
	var hasJdk bool
	for _, loc := range ownedLocations {
		p := loc.Path()
		results = append(results, p)
		if !hasJdk && strings.HasSuffix(p, "bin/javac") {
			hasJdk = true
		}
	}

	sort.Strings(results)

	return results, hasJdk
}

func jvmPurl(ri pkg.JavaVMRelease, version, vendor, product string) string {
	var qualifiers []packageurl.Qualifier
	if ri.SourceRepo != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repository_url",
			Value: ri.SourceRepo,
		})
	} else if ri.BuildSourceRepo != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repository_url",
			Value: ri.BuildSourceRepo,
		})
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		vendor,
		product,
		version,
		qualifiers,
		"")
	return pURL.ToString()
}

func jvmPrimaryVendorProduct(implementor, path, imageType string, hasJdk bool) (string, string) {
	implementor = strings.ReplaceAll(strings.ToLower(implementor), " ", "")

	pickProduct := func() string {
		if hasJdk || jvmProjectByType(imageType) == jdk {
			return jdk
		}
		return jre
	}

	switch {
	case strings.Contains(implementor, "azul") || strings.Contains(path, "zulu"):
		return "azul", "zulu"

	case strings.Contains(implementor, "sun"):
		return "sun", pickProduct()

	case strings.Contains(implementor, "oracle") || strings.Contains(path, "oracle"):
		return oracleVendor, pickProduct()
	}
	return oracleVendor, openJdkProduct
}

func jvmCpes(version, primaryVendor, primaryProduct, imageType string, hasJdk bool) []cpe.CPE {
	// see https://github.com/anchore/syft/issues/2422 for more context

	var candidates []jvmCpeInfo

	newCandidate := func(ven, prod, ver string) {
		candidates = append(candidates, jvmCpeInfo{
			vendor:  ven,
			product: prod,
			version: ver,
		})
	}

	newEnterpriseCandidate := func(ven, ver string) {
		newCandidate(ven, jre, ver)
		if hasJdk || jvmProjectByType(imageType) == jdk {
			newCandidate(ven, jdk, ver)
		}
	}

	switch {
	case primaryVendor == "azul":
		newCandidate(primaryVendor, "zulu", version)
		newCandidate(oracleVendor, openJdkProduct, version)

	case primaryVendor == "sun":
		newEnterpriseCandidate(primaryVendor, version)

	case primaryVendor == oracleVendor && primaryProduct != openJdkProduct:
		newCandidate(primaryVendor, "java_se", version)
		newEnterpriseCandidate(primaryVendor, version)
	default:
		newCandidate(primaryVendor, primaryProduct, version)
	}

	var cpes []cpe.CPE
	for _, candidate := range candidates {
		c := newJvmCpe(candidate)
		if c == nil {
			continue
		}
		cpes = append(cpes, *c)
	}

	return cpes
}

func getJVMVersionAndUpdate(version string) (string, string) {
	hasPlus := strings.Contains(version, "+")
	hasUnderscore := strings.Contains(version, "_")

	switch {
	case hasUnderscore:
		// assume legacy version strings are provided
		// example: 1.8.0_302-b08
		fields := strings.Split(version, "_")
		if len(fields) == 2 {
			shortVer := fields[0]
			fields = strings.Split(fields[1], "-")
			return shortVer, fields[0]
		}
	case hasPlus:
		// assume JEP 223 version strings are provided
		// example: 9.0.1+20
		fields := strings.Split(version, "+")
		return fields[0], ""
	}

	// this could be a legacy or modern string that does not have an update
	return version, ""
}

func newJvmCpe(candidate jvmCpeInfo) *cpe.CPE {
	if candidate.vendor == "" || candidate.product == "" || candidate.version == "" {
		return nil
	}

	shortVer, update := getJVMVersionAndUpdate(candidate.version)

	if shortVer == "" {
		return nil
	}

	if update != "" && !strings.Contains(strings.ToLower(update), "update") {
		update = "update" + trim0sFromLeft(update)
	}

	return &cpe.CPE{
		Attributes: cpe.Attributes{
			Part:    "a",
			Vendor:  candidate.vendor,
			Product: candidate.product,
			Version: shortVer,
			Update:  update,
		},
		// note: we must use a declared source here. Though we are not directly raising up raw CPEs from cataloged material,
		// these are vastly more reliable and accurate than what would be generated from the cpe generator logic.
		// We want these CPEs to override any generated CPEs (and in fact prevent the generation of CPEs for these packages altogether).
		Source: cpe.DeclaredSource,
	}
}

func jvmProjectByType(ty string) string {
	if strings.Contains(strings.ToLower(ty), jre) {
		return jre
	}
	return jdk
}

// jvmPackageVersion attempts to extract the correct version value for the JVM given a platter of version strings to choose
// from, and makes special consideration to what a valid version is relative to JEP 223.
//
// example version values (openjdk >8):
//
//	IMPLEMENTOR_VERSION   "Temurin-21.0.4+7"
//	JAVA_RUNTIME_VERSION  "21.0.4+7-LTS"
//	FULL_VERSION          "21.0.4+7-LTS"
//	SEMANTIC_VERSION      "21.0.4+7"
//	JAVA_VERSION          "21.0.4"
//
// example version values (openjdk 8):
//
//	JAVA_VERSION       "1.8.0_422"
//	FULL_VERSION       "1.8.0_422-b05"
//	SEMANTIC_VERSION   "8.0.422+5"
//
// example version values (openjdk 8, but older):
//
//	JAVA_VERSION       "1.8.0_302"
//	FULL_VERSION       "1.8.0_302-b08"
//	SEMANTIC_VERSION   "8.0.302+8"
//
// example version values (oracle):
//
//	IMPLEMENTOR_VERSION   (missing)
//	JAVA_RUNTIME_VERSION  "22.0.2+9-70"
//	JAVA_VERSION          "22.0.2"
//
// example version values (mariner):
//
//	IMPLEMENTOR_VERSION   "Microsoft-9889599"
//	JAVA_RUNTIME_VERSION  "17.0.12+7-LTS"
//	JAVA_VERSION          "17.0.12"
//
// example version values (amazon):
//
//	IMPLEMENTOR_VERSION    "Corretto-17.0.12.7.1"
//	JAVA_RUNTIME_VERSION   "17.0.12+7-LTS"
//	JAVA_VERSION           "17.0.12"
//
// JEP 223 changes to JVM version string in the following way:
//
//	                     Pre JEP 223             Post JEP 223
//	Release Type    long           short    long           short
//	------------    --------------------    --------------------
//	Early Access    1.9.0-ea-b19    9-ea    9-ea+19        9-ea
//	Major           1.9.0-b100      9       9+100          9
//	Security #1     1.9.0_5-b20     9u5     9.0.1+20       9.0.1
//	Security #2     1.9.0_11-b12    9u11    9.0.2+12       9.0.2
//	Minor #1        1.9.0_20-b62    9u20    9.1.2+62       9.1.2
//	Security #3     1.9.0_25-b15    9u25    9.1.3+15       9.1.3
//	Security #4     1.9.0_31-b08    9u31    9.1.4+8        9.1.4
//	Minor #2        1.9.0_40-b45    9u40    9.2.4+45       9.2.4
//
// What does this mean for us? In terms of the version selected, use semver-compliant strings when available.
//
// In terms of where to get the version:
//
//	SEMANTIC_VERSION      Reasonably prevalent, but most accurate in terms of comparable versions
//	JAVA_RUNTIME_VERSION  Reasonable prevalent, but difficult to distinguish pre-release info vs aux info (jep 223 sensitive)
//	FULL_VERSION          Reasonable prevalent, but difficult to distinguish pre-release info vs aux info (jep 223 sensitive)
//	JAVA_VERSION          Most prevalent, but least specific (jep 223 sensitive)
//	IMPLEMENTOR_VERSION   Unusable or missing in some cases
func jvmPackageVersion(ri *pkg.JavaVMRelease) string {
	var version string
	switch {
	case ri.JavaRuntimeVersion != "":
		return ri.JavaRuntimeVersion
	case ri.FullVersion != "":
		// if the full version major version matches the java version major version, then use the full version
		fullMajor := strings.Split(ri.FullVersion, ".")[0]
		javaMajor := strings.Split(ri.JavaVersion, ".")[0]
		if fullMajor == javaMajor {
			return ri.FullVersion
		}
		fallthrough
	case ri.JavaVersion != "":
		return ri.JavaVersion
	}

	return version
}

func trim0sFromLeft(v string) string {
	if v == "0" {
		return v
	}
	return strings.TrimLeft(v, "0")
}

func parseJvmReleaseInfo(r io.ReadCloser) (*pkg.JavaVMRelease, error) {
	defer r.Close()

	data := make(map[string]any)
	scanner := bufio.NewScanner(io.LimitReader(r, 500*stereoFile.KB))

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := strings.Trim(parts[1], `"`)

		if key == "MODULES" {
			data[key] = strings.Split(value, " ")
		} else {
			data[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// if we're missing key fields, then we don't have a JVM release file
	if data["JAVA_VERSION"] == nil && data["JAVA_RUNTIME_VERSION"] == nil {
		return nil, nil
	}

	var ri pkg.JavaVMRelease
	if err := mapstructure.Decode(data, &ri); err != nil {
		return nil, err
	}

	return &ri, nil
}
