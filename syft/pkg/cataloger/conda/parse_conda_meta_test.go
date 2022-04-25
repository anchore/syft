package conda

import (
    //"github.com/anchore/syft/syft/source"
    "github.com/anchore/syft/syft/pkg"
    "os"
    "testing"
)

func TestParseCondaMeta_Arrow(t *testing.T) {
    
    expected := pkg.CondaPackageMetadata {
        Channel: "https://conda.anaconda.org/conda-forge/linux-64",
        ExtractedPackageDir: "/opt/conda/pkgs/arrow-cpp-0.2.post-0",
        FN: "arrow-cpp-0.2.post-0.tar.bz2",
        PackageTarballFullPath: "/opt/conda/pkgs/arrow-cpp-0.2.post-0.tar.bz2",
        SHA256: "b29bca91b55cf246b0212e4ad1a3496744c636cb4a54ba4c383a0dcf79781f92",
        URL: "https://conda.anaconda.org/conda-forge/linux-64/arrow-cpp-0.2.post-0.tar.bz2",
        Version: "0.2.post",
    }

    fixture, err := os.Open("test-fixtures/conda-meta/arrow-cpp-0.2.post-0.json")
    if err != nil {
        t.Fatalf("failed to open test fixture: %+v", err)
    }

    actualCondaMeta, err := parseCondaMeta(fixture.Name(), fixture)
    if err != nil {
        t.Fatalf("failed to parse conda-meta: %+v", err)
    }

    if expected.Channel != actualCondaMeta.Channel {
        t.Fail()
    }

    if expected.ExtractedPackageDir != actualCondaMeta.ExtractedPackageDir {
        t.Fail()
    }

    if expected.FN != actualCondaMeta.FN {
        t.Fail()
    }
}
