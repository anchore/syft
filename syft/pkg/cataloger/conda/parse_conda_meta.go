package conda

/*
Parse conda package metadata file: $CONDA_PREFIX/conda-meta/*.json
*/

import (
    "bufio"
    "fmt"
    "io"
    "strings"
    "encoding/json"
    "github.com/anchore/syft/syft/pkg"
    "github.com/anchore/syft/syft/artifact"
    "github.com/anchore/syft/syft/pkg/cataloger/common"
)

type Path struct {
    _Path string `json:"_path"`
    PathType string `json:"path_type"`
    SHA256 string `json:"sha256"`
    SHA256InPrefix string `json:"sha256_in_prefix"`
    SizeInBytes int `json:"size_in_bytes"`
}

type CondaMeta struct {
    Build string `json:"build"`
    BuildNumber string `json:"build_number"`
    Channel string `json:"channel"`
    Constrains []string `json:"constrains"`
    Depends []string `json:"constrains"`
    ExtractedPackageDir string `json:"extracted_package_dir"`
    Features string `json:"features"` 
    Files []string `json:"files"` // list of files contained within a conda package
    FN string `json:"fn"` // filename of the conda package, usually a .tar.bz2
    License string `json:"license"`
    Link struct {
        Source string `json:"source"`
        Type string `json:"type"`
    } `json:"link"`
    MD5 string `json:"md5"`
    Name string `json:"name"`
    Noarch string `json:"noarch"`
    PackageTarballFullPath string `json:"package_tarball_full_path"`
    PackageType string `json:"package_type"`
    PathsData struct {
        Paths []Path `json:"paths"`
        PathsVersion int `json:"paths_version"`
    } `json:"paths_data"`
    RequestedSpec string `json:"requested_spec"`
    SHA256 string `json:"sha256"`
    Size int `json:"size"`
    Subdir string `json:"subdir"`
    Timestamp int `json:"timestamp"`
    TrackFeatures string `json:"track_features"`
    URL string `json:"url"`
    Version string `json:"version"`
}

// integrity check
var _ common.ParserFn = parseCondaMeta

func parseCondaMeta(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
    packages := make([]*pkg.Package, 0)

    json_decoder := json.NewDecoder(reader)

    return packages, nil, nil

}

