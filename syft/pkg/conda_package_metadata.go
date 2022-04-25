package pkg

import (
    "github.com/anchore/syft/syft/linux"
    "github.com/anchore/packageurl-go"
)

var _ urlIdentifier = (*CondaPackageMetadata)(nil)

type CondaPathMeta struct {
    Path string
    PathType string
    SHA256 string
}

type CondaPackageMetadata struct {
    Channel string
    ExtractedPackageDir string
    Files []string
    FN string
    PackageTarballFullPath string
    PathsData []CondaPathMeta
    SHA256 string
    URL string
    Version string
}

func (c CondaPackageMetadata) PackageURL(_ *linux.Release) string {
    pURL := packageurl.NewPackageURL(
        packageurl.TypeConda,
        "",
        c.FN,
        c.Version,
        nil,
        "",
    ).ToString()

    return pURL
}
