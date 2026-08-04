package perl

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// perllocal.pod stanzas look like this, one per install:
//
//	=head2 Mon Jul 27 20:10:38 2026: C<Module> L<Net::HTTP|Net::HTTP>
//	=item * C<installed into: /usr/local/lib/perl5/site_perl/5.40.4>
//	=item * C<VERSION: 6.24>
//
// The date prefix has changed across ExtUtils::MakeMaker versions (localtime became
// gmtime($ENV{SOURCE_DATE_EPOCH} || time) for reproducible builds), so the stanza is recognized by the
// C<Module> marker rather than by anything in the heading. Every EUMM version checked emits =head2, so
// the heading level is not known to vary; keying on the marker just means nothing here depends on it.
var (
	perllocalModulePattern  = regexp.MustCompile(`C<Module>\s+L<([^|>]+)`)
	perllocalInstalledInto  = regexp.MustCompile(`C<installed into:\s*([^>]*)>`)
	perllocalVersionPattern = regexp.MustCompile(`C<VERSION:\s*([^>]*)>`)
)

// perllocalEntry is one Module stanza of a perllocal.pod, in the order it was written.
type perllocalEntry struct {
	Module        string // as written, e.g. Net::HTTP
	InstalledInto string // the INSTALLSITELIB the installer recorded
	Version       string
}

// perllocalPod is a parsed perllocal.pod together with where it was found, since the file that supplied
// a version is recorded as supporting evidence on the package.
type perllocalPod struct {
	location file.Location
	entries  []perllocalEntry
}

// resolvePacklistVersions fills in the version of every package that came from a .packlist.
//
// perllocal.pod is the primary source because ExtUtils::MakeMaker writes it and the packlist from the
// same variables in the same install target: the packlist goes to $(SITEARCHEXP)/auto/$(FULLEXT)/.packlist
// while the stanza records "Module" "$(NAME)" with VERSION "$(VERSION)", and FULLEXT is NAME with :: turned
// into /. So the auto/ path segments and the stanza's module name are the same key. $(VERSION) is what EUMM
// evaluated at build time, so a version the module computes rather than declares is recorded correctly,
// which static .pm parsing cannot do at all.
//
// This is a processor rather than a per-packlist read because perllocal.pod is not a sibling of anything:
// EUMM writes it to DESTINSTALLARCHLIB, the core arch directory, even for site installs, so it has to be
// found with a resolver glob. There is one per install tree against many packlists, so it is parsed once
// here rather than once per packlist.
//
// It must run before mergeDistributions. Merging pairs a packlist package to its install.json package only
// when the versions agree or the packlist version is absent, so filling the version in afterwards would
// leave every distribution whose two evidence kinds disagree split into two packages.
func resolvePacklistVersions(_ context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if resolver == nil || len(pkgs) == 0 {
		return pkgs, rels, err
	}

	var pods []perllocalPod
	for _, location := range perllocalLocations(resolver) {
		if entries := readPerllocal(resolver, location); len(entries) > 0 {
			pods = append(pods, perllocalPod{location: location, entries: entries})
		}
	}

	for i := range pkgs {
		md, ok := pkgs[i].Metadata.(pkg.CpanDistribution)
		if !ok || md.MainModule == "" || pkgs[i].Version != "" {
			// not a packlist-derived package, so there is nothing to resolve
			continue
		}

		version, evidence := packlistVersion(resolver, pods, pkgs[i], md)
		if version == "" && evidence == nil {
			// still emitted with an empty version rather than dropped, so the distribution stays visible
			continue
		}

		pkgs[i].Version = version
		pkgs[i].PURL = packageURL(pkgs[i].Name, version, md.Author)
		if evidence != nil {
			locations := pkgs[i].Locations
			locations.Add(evidence.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
			pkgs[i].Locations = locations
		}

		// Version and Locations both participate in the package ID
		pkgs[i].SetID()
	}

	return pkgs, rels, err
}

// packlistVersion resolves one packlist package's version, preferring perllocal.pod and falling back to
// scraping $VERSION out of the distribution's main .pm. The fallback is not vestigial: NO_PERLLOCAL
// suppresses the file the same way NO_PACKLIST suppresses the packlist, and Module::Build and
// Module::Build::Tiny write packlists but no perllocal.pod at all.
func packlistVersion(resolver file.Resolver, pods []perllocalPod, p pkg.Package, md pkg.CpanDistribution) (string, *file.Location) {
	packlistPath := primaryPath(p)

	if version, location := perllocalVersion(pods, p.Name, packlistPath); version != "" {
		return version, location
	}

	pmLocation, ok := findFile(resolver, mainModuleFile(p.Name, md.Files))
	if !ok {
		return "", nil
	}

	return readVersionFromPM(resolver, pmLocation), &pmLocation
}

// perllocalVersion picks the stanza that describes the packlist at packlistPath, by three rules:
//
//  1. Key on the dashed module name: auto/Net/HTTP/.packlist and "Module Net::HTTP" both give Net-HTTP.
//  2. The stanza's "installed into" libdir must be a path prefix of the packlist, since in every standard
//     perl layout the arch directory nests under the lib directory. Where an image carries more than one
//     perl, the core libdir of one tree can also prefix-match another tree's packlist, so the longest
//     matching libdir wins. Without that a version from the wrong perl silently wins, which is worse than
//     no version at all.
//  3. The file is append-only, so an upgrade leaves a stale stanza beside the current one forever. Stanzas
//     are chronological, so the last match wins. The dates are not parsed; file order is the ordering.
func perllocalVersion(pods []perllocalPod, dashedName, packlistPath string) (string, *file.Location) {
	var (
		version    string
		evidence   *file.Location
		bestLibdir int
	)

	for i := range pods {
		for _, entry := range pods[i].entries {
			if entry.Version == "" || strings.ReplaceAll(entry.Module, "::", "-") != dashedName {
				continue
			}

			libdir := strings.TrimSuffix(entry.InstalledInto, "/")
			if libdir == "" || !strings.HasPrefix(normalizePath(packlistPath), normalizePath(libdir)+"/") {
				continue
			}

			// >= rather than > so that the last stanza of an equally specific libdir wins
			if len(libdir) >= bestLibdir {
				version, evidence, bestLibdir = entry.Version, &pods[i].location, len(libdir)
			}
		}
	}

	return version, evidence
}

// normalizePath makes the resolver's relative paths and perllocal's absolute libdirs comparable. A
// directory scan reports paths relative to its root, while perllocal records what the installer saw.
func normalizePath(p string) string {
	return "/" + strings.TrimPrefix(p, "/")
}

func perllocalLocations(resolver file.Resolver) []file.Location {
	locations, err := resolver.FilesByGlob("**/perllocal.pod")
	if err != nil {
		log.WithFields("error", err).Debug("unable to search for perllocal.pod")
		return nil
	}
	return locations
}

func readPerllocal(resolver file.Resolver, location file.Location) []perllocalEntry {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.WithFields("path", location.Path(), "error", err).Debug("unable to read perllocal.pod")
		return nil
	}
	defer internal.CloseAndLogError(reader, location.Path())

	return parsePerllocal(reader)
}

func parsePerllocal(r io.Reader) []perllocalEntry {
	var entries []perllocalEntry

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if match := perllocalModulePattern.FindStringSubmatch(line); match != nil {
			entries = append(entries, perllocalEntry{Module: strings.TrimSpace(match[1])})
			continue
		}

		if len(entries) == 0 {
			continue
		}

		current := &entries[len(entries)-1]
		if match := perllocalInstalledInto.FindStringSubmatch(line); match != nil {
			current.InstalledInto = strings.TrimSpace(match[1])
		}
		if match := perllocalVersionPattern.FindStringSubmatch(line); match != nil {
			current.Version = strings.TrimSpace(match[1])
		}
	}

	return entries
}

// primaryPath returns the path of the evidence the package was built from, which for a packlist package
// is the .packlist itself.
func primaryPath(p pkg.Package) string {
	for _, location := range p.Locations.ToSlice() {
		if location.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			return location.Path()
		}
	}
	return ""
}
