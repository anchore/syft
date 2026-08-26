package freebsd

import (
	"context"
	"database/sql"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// licenseLogicName maps the raw pkgng "licenselogic" column (see libpkg's lic_t enum) to a human readable name.
func licenseLogicName(logic int64) string {
	switch logic {
	case 1:
		return "single"
	case '|':
		return "or"
	case '&':
		return "and"
	default:
		return ""
	}
}

// parsePkgDB parses a FreeBSD pkgng "local.sqlite" database and returns the packages listed within it, as
// recorded in the "packages" and "files" tables.
func parsePkgDB(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	td := tmpdir.FromContext(ctx)
	if td == nil {
		return nil, nil, fmt.Errorf("no temp dir factory in context")
	}
	f, cleanup, err := td.NewFile("freebsd-pkgdb-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp pkgdb file: %w", err)
	}
	defer cleanup()
	defer f.Close()

	if _, err := io.Copy(f, reader); err != nil {
		return nil, nil, fmt.Errorf("failed to copy pkgdb contents to temp file: %w", err)
	}

	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open FreeBSD pkg database: %w", err)
	}
	defer db.Close()

	entries, order, err := fetchPackages(db)
	if err != nil {
		return nil, nil, err
	}

	if err := fetchFiles(db, entries); err != nil {
		return nil, nil, err
	}

	if err := fetchLicenses(db, entries); err != nil {
		return nil, nil, err
	}

	var pkgs []pkg.Package
	for _, id := range order {
		pkgs = append(pkgs, newPackage(ctx, reader.Location, *entries[id]))
	}

	return pkgs, nil, nil
}

func fetchPackages(db *sql.DB) (map[int64]*pkg.FreeBSDPkgDBEntry, []int64, error) {
	rows, err := db.Query(`
		SELECT id, origin, name, version, comment, desc, arch, maintainer, www, prefix,
		       flatsize, automatic, locked, licenselogic, manifestdigest, vital
		FROM packages
	`)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query packages table: %w", err)
	}
	defer rows.Close()

	entries := make(map[int64]*pkg.FreeBSDPkgDBEntry)
	var order []int64

	for rows.Next() {
		var (
			id                                                     int64
			origin, name, version, comment, desc, arch, maintainer string
			www, prefix, manifestdigest                            sql.NullString
			flatsize                                               int64
			automatic, locked, vital, licenselogic                 int64
		)

		if err := rows.Scan(&id, &origin, &name, &version, &comment, &desc, &arch, &maintainer,
			&www, &prefix, &flatsize, &automatic, &locked, &licenselogic, &manifestdigest, &vital); err != nil {
			return nil, nil, fmt.Errorf("failed to scan packages row: %w", err)
		}

		entries[id] = &pkg.FreeBSDPkgDBEntry{
			Origin:         origin,
			Name:           name,
			Version:        version,
			Comment:        comment,
			Description:    desc,
			Arch:           arch,
			Maintainer:     maintainer,
			WWW:            www.String,
			Prefix:         prefix.String,
			FlatSize:       flatsize,
			Automatic:      automatic != 0,
			Locked:         locked != 0,
			LicenseLogic:   licenseLogicName(licenselogic),
			ManifestDigest: manifestdigest.String,
			Vital:          vital != 0,
		}
		order = append(order, id)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to iterate packages rows: %w", err)
	}

	return entries, order, nil
}

// optionalFileColumns are columns of the "files" table that are not present in every observed pkgng schema
// version; missing columns are treated as empty rather than failing the query.
var optionalFileColumns = []string{"sha256", "uname", "gname"}

func fetchFiles(db *sql.DB, entries map[int64]*pkg.FreeBSDPkgDBEntry) error {
	available, err := tableColumns(db, "files")
	if err != nil {
		return fmt.Errorf("failed to inspect files table schema: %w", err)
	}

	var selectCols []string
	for _, c := range optionalFileColumns {
		if available[c] {
			selectCols = append(selectCols, c)
		}
	}

	query := "SELECT path, package_id"
	for _, c := range selectCols {
		query += ", " + c
	}
	query += " FROM files"

	rows, err := db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query files table: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			path      sql.NullString
			packageID sql.NullInt64
		)

		values := make([]sql.NullString, len(selectCols))
		dest := []any{&path, &packageID}
		for i := range selectCols {
			dest = append(dest, &values[i])
		}

		if err := rows.Scan(dest...); err != nil {
			return fmt.Errorf("failed to scan files row: %w", err)
		}

		if !packageID.Valid {
			continue
		}

		entry, ok := entries[packageID.Int64]
		if !ok {
			continue
		}

		col := func(name string) string {
			for i, c := range selectCols {
				if c == name {
					return values[i].String
				}
			}
			return ""
		}

		entry.Files = append(entry.Files, pkg.FreeBSDFileRecord{
			Path:      path.String,
			Digest:    stripDigestAlgoPrefix(col("sha256")),
			UserName:  col("uname"),
			GroupName: col("gname"),
		})
	}

	return rows.Err()
}

// tableColumns returns the set of column names present on the given table, so that queries can degrade
// gracefully against pkgng schema versions that don't include every optional column.
func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return nil, fmt.Errorf("failed to query table info for %q: %w", table, err)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var (
			cid       int64
			name      string
			ctype     string
			notNull   int64
			dfltValue sql.NullString
			pk        int64
		)

		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return nil, fmt.Errorf("failed to scan table info row: %w", err)
		}

		columns[name] = true
	}

	return columns, rows.Err()
}

// fetchLicenses populates each package entry with the license names attributed to it. License values are not
// stored directly on the "packages" table; they must be looked up via the "pkg_licenses" join table, which
// associates a package_id with a license_id found in the "licenses" table.
func fetchLicenses(db *sql.DB, entries map[int64]*pkg.FreeBSDPkgDBEntry) error {
	rows, err := db.Query(`
		SELECT pl.package_id, l.name
		FROM pkg_licenses pl
		JOIN licenses l ON l.id = pl.license_id
	`)
	if err != nil {
		return fmt.Errorf("failed to query pkg_licenses/licenses tables: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			packageID int64
			name      string
		)

		if err := rows.Scan(&packageID, &name); err != nil {
			return fmt.Errorf("failed to scan pkg_licenses row: %w", err)
		}

		entry, ok := entries[packageID]
		if !ok || name == "" {
			continue
		}

		entry.Licenses = append(entry.Licenses, name)
	}

	return rows.Err()
}
