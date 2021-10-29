package spdxhelpers

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/pkg"
)

func Files(packageSpdxID string, p *pkg.Package) (files []model.File, fileIDs []string, relationships []model.Relationship) {
	files = make([]model.File, 0)
	fileIDs = make([]string, 0)
	relationships = make([]model.Relationship, 0)

	if !hasMetadata(p) {
		return files, fileIDs, relationships
	}

	pkgFileOwner, ok := p.Metadata.(pkg.FileOwner)
	if !ok {
		return files, fileIDs, relationships
	}

	for _, ownedFilePath := range pkgFileOwner.OwnedFiles() {
		baseFileName := filepath.Base(ownedFilePath)
		pathHash := sha256.Sum256([]byte(ownedFilePath))
		fileSpdxID := model.ElementID(fmt.Sprintf("File-%s-%x", p.Name, pathHash)).String()

		fileIDs = append(fileIDs, fileSpdxID)

		files = append(files, model.File{
			FileName: ownedFilePath,
			Item: model.Item{
				Element: model.Element{
					SPDXID: fileSpdxID,
					Name:   baseFileName,
				},
			},
		})

		relationships = append(relationships, model.Relationship{
			SpdxElementID:      packageSpdxID,
			RelationshipType:   model.ContainsRelationship,
			RelatedSpdxElement: fileSpdxID,
		})
	}

	return files, fileIDs, relationships
}
