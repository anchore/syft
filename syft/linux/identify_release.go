package linux

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// returns a distro or nil
type parseFunc func(io.Reader) (*Release, error)

type parseEntry struct {
	path string
	fn   parseFunc
}

var identityFiles = []parseEntry{
	{
		// most distros provide a link at this location
		path: "/etc/os-release",
		fn:   parseOsRelease,
	},
	{
		// standard location for rhel & debian distros
		path: "/usr/lib/os-release",
		fn:   parseOsRelease,
	},
	{
		// check for centos:6
		path: "/etc/system-release-cpe",
		fn:   parseSystemReleaseCPE,
	},
	{
		// last ditch effort for determining older centos version distro information
		path: "/etc/redhat-release",
		fn:   parseRedhatRelease,
	},
	// /////////////////////////////////////////////////////////////////////////////////////////////////////
	// IMPORTANT! checking busybox must be last since other distros contain the busybox binary
	{
		// check for busybox
		path: "/bin/busybox",
		fn:   parseBusyBox,
	},
	// /////////////////////////////////////////////////////////////////////////////////////////////////////
}

// after a parser function returns a Release, it may have incomplete information; supplementers can be used to
// fill in missing details based on other files present in the filesystem
var supplementers = []func(file.Resolver, *Release){
	supplementDebianVersion,
}

// IdentifyRelease parses distro-specific files to discover and raise linux distribution release details.
func IdentifyRelease(resolver file.Resolver) *Release {
	logger := log.Nested("operation", "identify-release")
	for _, entry := range identityFiles {
		locations, err := resolver.FilesByPath(entry.path)
		if err != nil {
			logger.WithFields("error", err, "path", entry.path).Trace("unable to get path")
			continue
		}

		for _, location := range locations {
			release := tryParseReleaseInfo(resolver, location, logger, entry)
			if release != nil {
				for _, supplementer := range supplementers {
					supplementer(resolver, release)
				}
				return release
			}
		}
	}

	return nil
}

func tryParseReleaseInfo(resolver file.Resolver, location file.Location, logger logger.Logger, entry parseEntry) *Release {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		logger.WithFields("error", err, "path", location.RealPath).Trace("unable to get contents")
		return nil
	}
	defer internal.CloseAndLogError(contentReader, location.AccessPath)

	release, err := entry.fn(contentReader)
	if err != nil {
		logger.WithFields("error", err, "path", location.RealPath).Trace("unable to parse contents")
		return nil
	}

	return release
}

func parseOsRelease(r io.Reader) (*Release, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, value, ok := parseOsReleaseLine(line)
		if ok {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var idLike []string
	for _, s := range strings.Split(values["ID_LIKE"], " ") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		idLike = append(idLike, s)
	}

	rel := Release{
		PrettyName:       values["PRETTY_NAME"],
		Name:             values["NAME"],
		ID:               values["ID"],
		IDLike:           idLike,
		Version:          values["VERSION"],
		VersionID:        values["VERSION_ID"],
		VersionCodename:  values["VERSION_CODENAME"],
		BuildID:          values["BUILD_ID"],
		ImageID:          values["IMAGE_ID"],
		ImageVersion:     values["IMAGE_VERSION"],
		Variant:          values["VARIANT"],
		VariantID:        values["VARIANT_ID"],
		HomeURL:          values["HOME_URL"],
		SupportURL:       values["SUPPORT_URL"],
		BugReportURL:     values["BUG_REPORT_URL"],
		PrivacyPolicyURL: values["PRIVACY_POLICY_URL"],
		CPEName:          values["CPE_NAME"],
		SupportEnd:       values["SUPPORT_END"],
	}

	// don't allow for empty contents to result in a Release object being created
	if cmp.Equal(rel, Release{}) {
		return nil, nil
	}

	return &rel, nil
}

func parseOsReleaseLine(line string) (string, string, bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	// unquote
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if first == last && (first == '"' || first == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	// NOTE: per POSIX shell quoting rules, only double-quoted values should have escape
	// sequences interpreted, and single-quoted values should be literal. However, the
	// previous library (acobaugh/osrelease) applied escape replacement unconditionally
	// to all values regardless of quoting style. We preserve that behavior here for
	// backward compatibility.
	// replace \\ first so that e.g. \\" is not misinterpreted as \" + trailing char
	value = strings.ReplaceAll(value, `\\`, "\x00")
	value = strings.ReplaceAll(value, `\"`, `"`)
	value = strings.ReplaceAll(value, `\$`, `$`)
	value = strings.ReplaceAll(value, "\\`", "`")
	value = strings.ReplaceAll(value, "\x00", `\`)
	return key, value, true
}

var busyboxVersionMatcher = regexp.MustCompile(`BusyBox v(?P<version>[\d.]+)`)

func parseBusyBox(r io.Reader) (*Release, error) {
	results, err := internal.MatchNamedCaptureGroupsFromReader(busyboxVersionMatcher, r)
	if err != nil {
		return nil, err
	}
	if results == nil {
		return nil, nil
	}
	version := results["version"]
	if version == "" {
		return nil, nil
	}
	return simpleRelease("BusyBox v"+version, "busybox", version, ""), nil
}

// example CPE: cpe:/o:centos:linux:6:GA
var systemReleaseCpeMatcher = regexp.MustCompile(`cpe:\/o:(.*?):.*?:(.*?):.*?$`)

// parseSystemReleaseCPE parses the older centos (6) file to determine distro metadata.
// Returns the first matching CPE line found in the file.
func parseSystemReleaseCPE(r io.Reader) (*Release, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		match := systemReleaseCpeMatcher.FindStringSubmatch(line)
		if len(match) >= 3 {
			return simpleRelease(match[1], strings.ToLower(match[1]), match[2], match[0]), nil
		}
	}
	return nil, scanner.Err()
}

// example: "CentOS release 6.10 (Final)"
var redhatReleaseMatcher = regexp.MustCompile(`(?P<name>.*?)\srelease\s(?P<version>(?P<versionid>\d\.\d+).*)`)

// parseRedhatRelease is a fallback parsing method for determining distro information in older redhat versions.
// Returns the first matching release line found in the file.
func parseRedhatRelease(r io.Reader) (*Release, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		matches := internal.MatchNamedCaptureGroups(redhatReleaseMatcher, line)
		name := matches["name"]
		version := matches["version"]
		versionID := matches["versionid"]
		if name == "" || versionID == "" {
			continue
		}

		id := strings.ToLower(name)
		switch {
		case strings.HasPrefix(id, "red hat enterprise linux"):
			id = "rhel"
		case strings.HasPrefix(id, "centos"):
			version = versionID
		}

		return &Release{
			PrettyName: line,
			Name:       name,
			ID:         id,
			IDLike:     []string{id},
			Version:    version,
			VersionID:  versionID,
		}, nil
	}
	return nil, scanner.Err()
}

func simpleRelease(prettyName, name, version, cpe string) *Release {
	return &Release{
		PrettyName: prettyName,
		Name:       name,
		ID:         name,
		IDLike:     []string{name},
		Version:    version,
		VersionID:  version,
		CPEName:    cpe,
	}
}
