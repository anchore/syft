package alpine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parseApkDB

var (
	repoRegex = regexp.MustCompile(`(?m)^https://.*\.alpinelinux\.org/alpine/v([^/]+)/([a-zA-Z0-9_]+)$`)
)

type parsedData struct {
	License string `mapstructure:"L" json:"license"`
	pkg.ApkDBEntry
}

// parseApkDB parses packages from a given APK "installed" flat-file DB. For more
// information on specific fields, see https://wiki.alpinelinux.org/wiki/Apk_spec.
//
//nolint:funlen,gocognit
func parseApkDB(_ context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	scanner := bufio.NewScanner(reader)

	var apks []parsedData
	var currentEntry parsedData
	entryParsingInProgress := false
	fileParsingCtx := newApkFileParsingContext()

	// creating a dedicated append-like function here instead of using `append(...)`
	// below since there is nontrivial logic to be performed for each finalized apk
	// entry.
	appendApk := func(p parsedData) {
		if files := fileParsingCtx.files; len(files) >= 1 {
			// attached accumulated files to current package
			p.Files = files

			// reset file parsing for next use
			fileParsingCtx = newApkFileParsingContext()
		}

		nilFieldsToEmptySlice(&p)
		apks = append(apks, p)
	}

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// i.e. apk entry separator

			if entryParsingInProgress {
				// current entry is complete
				appendApk(currentEntry)
			}

			entryParsingInProgress = false

			// zero-out currentEntry for use by any future entry
			currentEntry = parsedData{}

			continue
		}

		field := parseApkField(line)
		if field == nil {
			log.Warnf("unable to parse field data from line %q", line)
			continue
		}
		if len(field.name) == 0 {
			log.Warnf("failed to parse field name from line %q", line)
			continue
		}
		if len(field.value) == 0 {
			log.Debugf("line %q: parsed field %q appears to have an empty value, skipping", line, field.name)
			continue
		}

		entryParsingInProgress = true

		field.apply(&currentEntry, fileParsingCtx)
	}

	if entryParsingInProgress {
		// There was no final empty line, so currentEntry hasn't been added to the
		// collection yet; but we've now reached the end of scanning, so let's be sure to
		// add currentEntry to the collection.
		appendApk(currentEntry)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse APK installed DB file: %w", err)
	}

	var r *linux.Release
	if env != nil {
		r = env.LinuxRelease
	}
	// this is somewhat ugly, but better than completely failing when we can't find the release,
	// e.g. embedded deeper in the tree, like containers or chroots.
	// but we now have no way of handling different repository sources. On the other hand,
	// we never could before this. At least now, we can handle some.
	// This should get fixed with https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10875
	if r == nil {
		// find the repositories file from the relative directory of the DB file
		releases := findReleases(resolver, reader.Location.RealPath)

		if len(releases) > 0 {
			r = &releases[0]
		}
	}

	pkgs := make([]pkg.Package, 0, len(apks))
	for _, apk := range apks {
		pkgs = append(pkgs, newPackage(apk, r, reader.Location))
	}

	return pkgs, discoverPackageDependencies(pkgs), nil
}

func findReleases(resolver file.Resolver, dbPath string) []linux.Release {
	if resolver == nil {
		return nil
	}

	reposLocation := path.Clean(path.Join(path.Dir(dbPath), "../../../etc/apk/repositories"))
	locations, err := resolver.FilesByPath(reposLocation)
	if err != nil {
		log.Tracef("unable to find APK repositories file %q: %+v", reposLocation, err)
		return nil
	}

	if len(locations) == 0 {
		return nil
	}
	location := locations[0]

	reposReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.Tracef("unable to fetch contents for APK repositories file %q: %+v", reposLocation, err)
		return nil
	}

	return parseReleasesFromAPKRepository(file.LocationReadCloser{
		Location:   location,
		ReadCloser: reposReader,
	})
}

func parseReleasesFromAPKRepository(reader file.LocationReadCloser) []linux.Release {
	var releases []linux.Release

	reposB, err := io.ReadAll(reader)
	if err != nil {
		log.Tracef("unable to read APK repositories file %q: %+v", reader.Location.RealPath, err)
		return nil
	}

	parts := repoRegex.FindAllStringSubmatch(string(reposB), -1)
	for _, part := range parts {
		if len(part) >= 3 {
			releases = append(releases, linux.Release{
				Name:      "Alpine Linux",
				ID:        "alpine",
				VersionID: part[1],
			})
		}
	}

	return releases
}

func parseApkField(line string) *apkField {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return nil
	}

	f := apkField{
		name:  parts[0],
		value: parts[1],
	}

	return &f
}

type apkField struct {
	name  string
	value string
}

//nolint:funlen
func (f apkField) apply(p *parsedData, ctx *apkFileParsingContext) {
	switch f.name {
	// APKINDEX field parsing

	case "P":
		p.Package = f.value
	case "o":
		p.OriginPackage = f.value
	case "m":
		p.Maintainer = f.value
	case "V":
		p.Version = f.value
	case "L":
		p.License = f.value
	case "A":
		p.Architecture = f.value
	case "U":
		p.URL = f.value
	case "T":
		p.Description = f.value
	case "S":
		i, err := strconv.Atoi(f.value)
		if err != nil {
			log.Warnf("unable to parse value %q for field %q: %w", f.value, f.name, err)
			return
		}

		p.Size = i
	case "I":
		i, err := strconv.Atoi(f.value)
		if err != nil {
			log.Warnf("unable to parse value %q for field %q: %w", f.value, f.name, err)
			return
		}

		p.InstalledSize = i
	case "D":
		deps := parseListValue(f.value)
		p.Dependencies = deps
	case "p":
		provides := parseListValue(f.value)
		p.Provides = provides
	case "C":
		p.Checksum = f.value
	case "c":
		p.GitCommit = f.value

	// File/directory field parsing:

	case "F":
		directory := path.Join("/", f.value)

		ctx.files = append(ctx.files, pkg.ApkFileRecord{Path: directory})
		ctx.indexOfLatestDirectory = len(ctx.files) - 1
	case "M":
		i := ctx.indexOfLatestDirectory
		latest := ctx.files[i]

		var ok bool
		latest.OwnerUID, latest.OwnerGID, latest.Permissions, ok = processFileInfo(f.value)
		if !ok {
			log.Warnf("unexpected value for APK ACL field %q: %q", f.name, f.value)
			return
		}

		// save updated directory
		ctx.files[i] = latest
	case "R":
		var regularFile string

		dirIndex := ctx.indexOfLatestDirectory
		if dirIndex < 0 {
			regularFile = path.Join("/", f.value)
		} else {
			latestDirPath := ctx.files[dirIndex].Path
			regularFile = path.Join(latestDirPath, f.value)
		}

		ctx.files = append(ctx.files, pkg.ApkFileRecord{Path: regularFile})
		ctx.indexOfLatestRegularFile = len(ctx.files) - 1
	case "a":
		i := ctx.indexOfLatestRegularFile
		latest := ctx.files[i]

		var ok bool
		latest.OwnerUID, latest.OwnerGID, latest.Permissions, ok = processFileInfo(f.value)
		if !ok {
			log.Warnf("unexpected value for APK ACL field %q: %q", f.name, f.value)
			return
		}

		// save updated file
		ctx.files[i] = latest
	case "Z":
		i := ctx.indexOfLatestRegularFile
		latest := ctx.files[i]
		latest.Digest = processChecksum(f.value)

		// save updated file
		ctx.files[i] = latest
	}
}

func processFileInfo(v string) (uid, gid, perms string, ok bool) {
	ok = false

	fileInfo := strings.Split(v, ":")
	if len(fileInfo) < 3 {
		return
	}

	uid = fileInfo[0]
	gid = fileInfo[1]
	perms = fileInfo[2]

	// note: there are more optional fields available that we are not capturing,
	// e.g.: "0:0:755:Q1JaDEHQHBbizhEzoWK1YxuraNU/4="

	ok = true
	return
}

// apkFileParsingContext helps keep track of what file data has been captured so far for the APK currently being parsed.
type apkFileParsingContext struct {
	files                    []pkg.ApkFileRecord
	indexOfLatestDirectory   int
	indexOfLatestRegularFile int
}

func newApkFileParsingContext() *apkFileParsingContext {
	return &apkFileParsingContext{
		indexOfLatestDirectory:   -1, // no directories yet
		indexOfLatestRegularFile: -1, // no regular files yet
	}
}

// parseListValue parses a space-separated list from an apk entry field value.
func parseListValue(value string) []string {
	items := strings.Split(value, " ")
	if len(items) >= 1 {
		return items
	}

	return nil
}

func nilFieldsToEmptySlice(p *parsedData) {
	if p.Dependencies == nil {
		p.Dependencies = []string{}
	}

	if p.Provides == nil {
		p.Provides = []string{}
	}

	if p.Files == nil {
		p.Files = []pkg.ApkFileRecord{}
	}
}

func processChecksum(value string) *file.Digest {
	// from: https://wiki.alpinelinux.org/wiki/Apk_spec
	// The package checksum field is the SHA1 hash of the second gzip stream (control stream) in the package. The
	// binary hash digest is base64 encoded. This is prefixed with Q1 to differentiate it from the MD5 hashes
	// used in older index formats. It is not possible to compute this checksum with standard command line tools
	// but the apk-tools can compute it in their index operation.

	// based on https://github.com/alpinelinux/apk-tools/blob/dd1908f2fc20b4cfe2c15c55fafaa5fadfb599dc/src/blob.c#L379-L393
	// it seems that the old md5 checksum value was only the hex representation (not base64)
	algorithm := "md5"
	if strings.HasPrefix(value, "Q1") {
		algorithm = "'Q1'+base64(sha1)"
	}

	return &file.Digest{
		Algorithm: algorithm,
		Value:     value,
	}
}

func discoverPackageDependencies(pkgs []pkg.Package) (relationships []artifact.Relationship) {
	// map["provides" string] -> packages that provide the "p" key
	lookup := make(map[string][]pkg.Package)
	// read "Provides" (p) and add as keys for lookup keys as well as package names
	for _, p := range pkgs {
		apkg, ok := p.Metadata.(pkg.ApkDBEntry)
		if !ok {
			log.Warnf("cataloger failed to extract apk 'provides' metadata for package %+v", p.Name)
			continue
		}
		lookup[p.Name] = append(lookup[p.Name], p)
		for _, provides := range apkg.Provides {
			k := stripVersionSpecifier(provides)
			lookup[k] = append(lookup[k], p)
		}
	}

	// read "Pull Dependencies" (D) and match with keys
	for _, p := range pkgs {
		apkg, ok := p.Metadata.(pkg.ApkDBEntry)
		if !ok {
			log.Warnf("cataloger failed to extract apk dependency metadata for package %+v", p.Name)
			continue
		}

		for _, depSpecifier := range apkg.Dependencies {
			// use the lookup to find what pkg we depend on
			dep := stripVersionSpecifier(depSpecifier)
			for _, depPkg := range lookup[dep] {
				// this is a pkg that package "p" depends on... make a relationship
				relationships = append(relationships, artifact.Relationship{
					From: depPkg,
					To:   p,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}
	return relationships
}

func stripVersionSpecifier(s string) string {
	// examples:
	// musl>=1                 --> musl
	// cmd:scanelf=1.3.4-r0    --> cmd:scanelf

	items := internal.SplitAny(s, "<>=")
	if len(items) == 0 {
		return s
	}

	return items[0]
}
