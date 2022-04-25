package conda

/*
Parse conda package metadata file: $CONDA_PREFIX/conda-meta/*.json
*/

import (
    "fmt"
    "io"
    "encoding/json"
    "github.com/anchore/syft/syft/pkg"
    //"github.com/anchore/syft/syft/artifact"
    //"github.com/anchore/syft/syft/pkg/cataloger/common"
)

type Path struct {
    Path string `json:"_path"`
    PathType string `json:"path_type"`
    SHA256 string `json:"sha256"`
    SHA256InPrefix string `json:"sha256_in_prefix"`
    SizeInBytes int `json:"size_in_bytes"`
}

type PathsData struct {
    Paths []Path `json:"paths"`
    PathsVersion int `json:"paths_version"`
}

type CondaMeta struct {
    Build string `json:"build"`
    BuildNumber int `json:"build_number"`
    Channel string `json:"channel"`
    Constrains []string `json:"constrains"`
    Depends []string `json:"depends"`
    ExtractedPackageDir string `json:"extracted_package_dir"`
    Features string `json:"features"` 
    Files []string `json:"files"` // list of files contained within a conda package
    FN string `json:"fn"` // filename of the conda package, usually a .tar.bz2
    License string `json:"license"`
    Link struct {
        Source string `json:"source"`
        Type int `json:"type"`
    } `json:"link"`
    MD5 string `json:"md5"`
    Name string `json:"name"` // common name of the package
    Noarch string `json:"noarch"`
    PackageTarballFullPath string `json:"package_tarball_full_path"`
    PackageType string `json:"package_type"`
    PathsData PathsData  `json:"paths_data"`
    RequestedSpec string `json:"requested_spec"`
    SHA256 string `json:"sha256"`
    Size int `json:"size"`
    Subdir string `json:"subdir"`
    Timestamp int `json:"timestamp"`
    TrackFeatures string `json:"track_features"`
    URL string `json:"url"`
    Version string `json:"version"`
}

func parseCondaMeta(_ string, reader io.Reader) (*pkg.CondaPackageMetadata, error) {

    json_decoder := json.NewDecoder(reader)
    
    var condaPkgMeta CondaMeta
    if err := json_decoder.Decode(&condaPkgMeta); err == io.EOF {
        return nil, fmt.Errorf("Failed to parse conda-meta/*.json file: %w", err)
    } else if err != nil {
        return nil, fmt.Errorf("Failed to parse conda-meta/*.json file: %w", err)
    }
    
    paths := make([]pkg.CondaPathMeta, 0)

    for _, pathEntry := range condaPkgMeta.PathsData.Paths {
        paths = append(paths, pkg.CondaPathMeta{
            Path: pathEntry.Path,
            PathType: pathEntry.PathType,
            SHA256: pathEntry.SHA256,
        })
    }

    condaPackageMetadata := pkg.CondaPackageMetadata {
        Channel: condaPkgMeta.Channel,
        ExtractedPackageDir: condaPkgMeta.ExtractedPackageDir,
        Files: condaPkgMeta.Files,
        FN: condaPkgMeta.FN,
        PackageTarballFullPath: condaPkgMeta.PackageTarballFullPath,
        PathsData: paths,
        SHA256: condaPkgMeta.SHA256,
        URL: condaPkgMeta.URL,
        Version: condaPkgMeta.Version,
    }
    return &condaPackageMetadata, nil
}

