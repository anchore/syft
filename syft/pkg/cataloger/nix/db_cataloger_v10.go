package nix

import (
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

var _ dbProcessor = processV10DB

func processV10DB(config Config, dbLocation file.Location, resolver file.Resolver, catalogerName string) ([]pkg.Package, []artifact.Relationship, error) {
	dbContents, err := resolver.FileContentsByLocation(dbLocation)
	defer internal.CloseAndLogError(dbContents, dbLocation.RealPath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read Nix database: %w", err)
	}

	tempDB, err := createTempDB(dbContents)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temporary database: %w", err)
	}
	defer os.RemoveAll(tempDB.Name())

	db, err := sql.Open("sqlite", tempDB.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetConnMaxLifetime(0)
	defer db.Close()

	packageEntries, err := extractV10DBPackages(config, db, dbLocation, resolver)
	if err != nil {
		return nil, nil, err
	}

	pkgs, relationships, err := finalizeV10DBResults(db, packageEntries, catalogerName)
	if err != nil {
		return nil, nil, err
	}

	return pkgs, relationships, nil
}

func extractV10DBPackages(config Config, db *sql.DB, dbLocation file.Location, resolver file.Resolver) (map[int]*dbPackageEntry, error) {
	pkgs, err := extractV10DBValidPaths(config, db, dbLocation, resolver)
	if err != nil {
		return nil, err
	}

	err = extractV10DBDerivationOutputs(db, pkgs)
	if err != nil {
		return nil, err
	}

	return pkgs, nil
}

func extractV10DBValidPaths(config Config, db *sql.DB, dbLocation file.Location, resolver file.Resolver) (map[int]*dbPackageEntry, error) {
	packages := make(map[int]*dbPackageEntry)

	rows, err := db.Query("SELECT id, path, hash, deriver FROM ValidPaths")
	if err != nil {
		return nil, fmt.Errorf("failed to query ValidPaths: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var path, hash, deriver sql.NullString

		if err := rows.Scan(&id, &path, &hash, &deriver); err != nil {
			return nil, fmt.Errorf("failed to scan ValidPaths row: %w", err)
		}

		if !path.Valid {
			continue
		}

		nsp := parseNixStorePath(path.String)
		if nsp == nil {
			nsp = &nixStorePath{}
		}
		// always trust the DB values over string parsing
		nsp.OutputHash = hash.String
		nsp.StorePath = path.String

		var files []string
		if config.CaptureOwnedFiles {
			files = listOutputPaths(path.String, resolver)
		}

		df, err := newDerivationFromPath(deriver.String, resolver)
		if err != nil {
			log.WithFields("path", deriver.String, "error", err).Trace("unable to find derivation")
			df = nil
		}

		packages[id] = &dbPackageEntry{
			ID:             id,
			nixStorePath:   *nsp,
			derivationFile: df,
			DeriverPath:    deriver.String,
			Location:       &dbLocation,
			Files:          files,
		}
	}

	return packages, nil
}

func listOutputPaths(storePath string, resolver file.Resolver) []string {
	if storePath == "" {
		return nil
	}
	searchGlob := storePath + "/**/*"
	locations, err := resolver.FilesByGlob(searchGlob)
	if err != nil {
		log.WithFields("path", storePath, "error", err).Trace("unable to find output paths")
		return nil
	}

	return filePaths(locations)
}

func extractV10DBDerivationOutputs(db *sql.DB, packages map[int]*dbPackageEntry) error {
	outputRows, err := db.Query("SELECT drv, id, path FROM DerivationOutputs")
	if err != nil {
		return fmt.Errorf("failed to query DerivationOutputs: %w", err)
	}
	defer outputRows.Close()

	pkgsByPath := make(map[string]*dbPackageEntry)
	for _, p := range packages {
		pkgsByPath[p.StorePath] = p
	}

	for outputRows.Next() {
		var drvID int
		var outputID, outputPath string

		if err := outputRows.Scan(&drvID, &outputID, &outputPath); err != nil {
			return fmt.Errorf("failed to scan DerivationOutputs row: %w", err)
		}

		if _, ok := pkgsByPath[outputPath]; !ok {
			continue
		}
		pkgsByPath[outputPath].Output = outputID
		pkgsByPath[outputPath].DrvID = drvID
	}

	return nil
}

func finalizeV10DBResults(db *sql.DB, packageEntries map[int]*dbPackageEntry, catalogerName string) ([]pkg.Package, []artifact.Relationship, error) {
	// make Syft packages for each package entry
	syftPackages := make(map[int]pkg.Package)
	for id, entry := range packageEntries {
		syftPackages[id] = newDBPackage(entry, catalogerName)
	}

	var relationships []artifact.Relationship

	query := `
	   SELECT r.referrer, r.reference
	   FROM Refs r
	   JOIN ValidPaths v1 ON r.referrer = v1.id
	   JOIN ValidPaths v2 ON r.reference = v2.id
	`

	refRows, err := db.Query(query)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query Refs with ValidPaths JOIN: %w", err)
	}
	defer refRows.Close()

	relExists := make(map[int]map[int]bool)

	for refRows.Next() {
		var referrerID, referenceID int

		if err := refRows.Scan(&referrerID, &referenceID); err != nil {
			return nil, nil, fmt.Errorf("failed to scan Refs row: %w", err)
		}

		if referrerID == referenceID {
			// skip self-references
			continue
		}

		referrer, refExists := syftPackages[referrerID]
		reference, refeeExists := syftPackages[referenceID]

		if !refExists || !refeeExists {
			// only include relationships for packages we have discovered
			continue
		}

		if _, ok := relExists[referrerID]; !ok {
			relExists[referrerID] = make(map[int]bool)
		}

		if relExists[referrerID][referenceID] {
			// deduplicate existing relationships
			continue
		}

		relExists[referrerID][referenceID] = true

		rel := artifact.Relationship{
			From: reference,
			To:   referrer,
			Type: artifact.DependencyOfRelationship,
		}

		relationships = append(relationships, rel)
	}

	var pkgs []pkg.Package
	for _, p := range syftPackages {
		pkgs = append(pkgs, p)
	}

	return pkgs, relationships, nil
}

func createTempDB(content io.ReadCloser) (*os.File, error) {
	tempFile, err := os.CreateTemp("", "nix-db-*.sqlite")
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(tempFile, content)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return nil, err
	}

	return tempFile, nil
}
