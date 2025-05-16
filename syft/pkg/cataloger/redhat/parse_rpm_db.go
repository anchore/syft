package redhat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseRpmDB parses an "Packages" RPM DB and returns the Packages listed within it.
//
//nolint:funlen
func parseRpmDB(ctx context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	f, err := os.CreateTemp("", "rpmdb")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp rpmdb file: %w", err)
	}

	defer func() {
		err = f.Close()
		if err != nil {
			log.Errorf("failed to close temp rpmdb file: %+v", err)
		}
		err = os.Remove(f.Name())
		if err != nil {
			log.Errorf("failed to remove temp rpmdb file: %+v", err)
		}
	}()

	_, err = io.Copy(f, reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to copy rpmdb contents to temp file: %w", err)
	}

	db, err := rpmdb.Open(f.Name())
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()

	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, nil, err
	}

	var allPkgs []pkg.Package

	var distro *linux.Release
	if env != nil {
		distro = env.LinuxRelease
	}

	var errs error
	for _, entry := range pkgList {
		if entry == nil {
			continue
		}

		files, err := extractRpmFileRecords(resolver, *entry)
		errs = unknown.Join(errs, err)

		// there is a period of time when RPM DB entries contain both PGP and RSA signatures that are the same.
		// This appears to be a holdover, where nowadays only the RSA Header is used.
		sigs, err := parseSignatures(strings.TrimSpace(entry.PGP), strings.TrimSpace(entry.RSAHeader))
		if err != nil {
			log.WithFields("error", err, "location", reader.RealPath, "pkg", fmt.Sprintf("%s@%s", entry.Name, entry.Version)).Trace("unable to parse signatures for package %s", entry.Name)
			sigs = nil
		}

		metadata := pkg.RpmDBEntry{
			Name:            entry.Name,
			Version:         entry.Version,
			Epoch:           entry.Epoch,
			Arch:            entry.Arch,
			Release:         entry.Release,
			SourceRpm:       entry.SourceRpm,
			Signatures:      sigs,
			Vendor:          entry.Vendor,
			Size:            entry.Size,
			ModularityLabel: &entry.Modularitylabel,
			Files:           files,
			Provides:        entry.Provides,
			Requires:        entry.Requires,
		}

		p := newDBPackage(
			ctx,
			reader.Location,
			metadata,
			distro,
			[]string{entry.License},
		)

		if !pkg.IsValid(&p) {
			log.WithFields("location", reader.RealPath, "pkg", fmt.Sprintf("%s@%s", entry.Name, entry.Version)).
				Warn("ignoring invalid package found in RPM DB")
			errs = unknown.Appendf(errs, reader, "invalild package found; name: %s, version: %s", entry.Name, entry.Version)
			continue
		}

		p.SetID()
		allPkgs = append(allPkgs, p)
	}

	if errs == nil && len(allPkgs) == 0 {
		errs = fmt.Errorf("unable to determine packages")
	}

	return allPkgs, nil, errs
}

func parseSignatures(sigs ...string) ([]pkg.RpmSignature, error) {
	var parsedSigs []pkg.RpmSignature
	var errs error
	for _, sig := range sigs {
		if sig == "" {
			continue
		}
		parts := strings.Split(sig, ",")
		if len(parts) != 3 {
			errs = errors.Join(fmt.Errorf("invalid signature format: %s", sig))
			continue
		}

		methodParts := strings.SplitN(strings.TrimSpace(parts[0]), "/", 2)
		if len(methodParts) != 2 {
			errs = errors.Join(fmt.Errorf("invalid signature method format: %s", parts[0]))
			continue
		}

		pka := strings.TrimSpace(methodParts[0])
		hash := strings.TrimSpace(methodParts[1])

		if pka == "" || hash == "" {
			errs = errors.Join(fmt.Errorf("invalid signature method values: public-key=%q hash=%q", pka, hash))
			continue
		}

		created := strings.TrimSpace(parts[1])
		if created == "" {
			errs = errors.Join(fmt.Errorf("invalid signature created value: %q", parts[1]))
			continue
		}

		issuerFields := strings.Split(strings.TrimSpace(parts[2]), " ")
		var issuer string
		switch len(issuerFields) {
		case 0:
			errs = errors.Join(fmt.Errorf("no signature issuer value: %q", parts[2]))
		case 1:
			issuer = issuerFields[0]
		default:
			issuer = issuerFields[len(issuerFields)-1]
			if issuer == "" {
				errs = errors.Join(fmt.Errorf("invalid signature issuer value: %q", parts[2]))
				continue
			}
		}

		if len(issuer) < 5 {
			errs = errors.Join(fmt.Errorf("invalid signature issuer length: %q", parts[2]))
			continue
		}

		parsedSig := pkg.RpmSignature{
			PublicKeyAlgorithm: pka,
			HashAlgorithm:      hash,
			Created:            created,
			IssuerKeyID:        issuer,
		}
		parsedSigs = append(parsedSigs, parsedSig)
	}
	return parsedSigs, errs
}

// The RPM naming scheme is [name]-[version]-[release]-[arch], where version is implicitly expands to [epoch]:[version].
// RPM version comparison depends on comparing at least the version and release fields together as a subset of the
// naming scheme. This toELVersion function takes a RPM DB package information and converts it into a minimally comparable
// version string, containing epoch (optional), version, and release information. Epoch is an optional field and can be
// assumed to be 0 when not provided for comparison purposes, however, if the underlying RPM DB entry does not have
// an epoch specified it would be slightly disingenuous to display a value of 0.
func toELVersion(epoch *int, version, release string) string {
	if epoch != nil {
		return fmt.Sprintf("%d:%s-%s", *epoch, version, release)
	}
	return fmt.Sprintf("%s-%s", version, release)
}

func extractRpmFileRecords(resolver file.PathResolver, entry rpmdb.PackageInfo) ([]pkg.RpmFileRecord, error) {
	var records = make([]pkg.RpmFileRecord, 0)

	files, err := entry.InstalledFiles()
	if err != nil {
		log.Debugf("unable to parse listing of installed files for RPM DB entry: %s", err.Error())
		return records, fmt.Errorf("unable to parse listing of installed files for RPM DB entry: %w", err)
	}

	for _, record := range files {
		// only persist RPMDB file records which exist in the image/directory, otherwise ignore them
		if resolver.HasPath(record.Path) {
			records = append(records, pkg.RpmFileRecord{
				Path: record.Path,
				Mode: pkg.RpmFileMode(record.Mode),
				Size: int(record.Size),
				Digest: file.Digest{
					Value:     record.Digest,
					Algorithm: entry.DigestAlgorithm.String(),
				},
				UserName:  record.Username,
				GroupName: record.Groupname,
				Flags:     record.Flags.String(),
			})
		}
	}
	return records, nil
}
