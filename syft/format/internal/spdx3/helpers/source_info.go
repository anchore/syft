package helpers

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

//nolint:funlen, gocyclo
func SourceInfo(p pkg.Package) string {
	answer := ""
	switch p.Type {
	case pkg.AlpmPkg:
		answer = "acquired package info from ALPM DB"
	case pkg.RpmPkg:
		answer = "acquired package info from RPM DB"
	case pkg.ApkPkg:
		answer = "acquired package info from APK DB"
	case pkg.BitnamiPkg:
		answer = "acquired package info from a Bitnami SBOM"
	case pkg.DartPubPkg:
		answer = "acquired package info from pubspec manifest"
	case pkg.DebPkg:
		answer = "acquired package info from DPKG DB"
	case pkg.DotnetPkg:
		answer = "acquired package info from dotnet project assets file"
	case pkg.NpmPkg:
		answer = "acquired package info from installed node module manifest file"
	case pkg.PythonPkg:
		answer = "acquired package info from installed python package manifest file"
	case pkg.JavaPkg, pkg.JenkinsPluginPkg:
		answer = "acquired package info from installed java archive"
	case pkg.GemPkg:
		answer = "acquired package info from installed gem metadata file"
	case pkg.GoModulePkg:
		answer = "acquired package info from go module information"
	case pkg.GraalVMNativeImagePkg:
		answer = "acquired package info from GraalVM native image"
	case pkg.RustPkg:
		answer = "acquired package info from rust cargo manifest"
	case pkg.PhpComposerPkg:
		answer = "acquired package info from PHP composer manifest"
	case pkg.PhpPearPkg:
		answer = "acquired package info from PHP Pear manifest"
	case pkg.PhpPeclPkg:
		answer = "acquired package info from PHP Pecl manifest"
	case pkg.CocoapodsPkg:
		answer = "acquired package info from installed cocoapods manifest file"
	case pkg.ConanPkg:
		answer = "acquired package info from conan manifest"
	case pkg.PortagePkg:
		answer = "acquired package info from portage DB"
	case pkg.HackagePkg:
		answer = "acquired package info from cabal or stack manifest files"
	case pkg.HexPkg:
		answer = "acquired package info from rebar3 or mix manifest file"
	case pkg.ErlangOTPPkg:
		answer = "acquired package info from ErLang application resource file"
	case pkg.LinuxKernelPkg:
		answer = "acquired package info from linux kernel archive"
	case pkg.LinuxKernelModulePkg:
		answer = "acquired package info from linux kernel module files"
	case pkg.NixPkg:
		answer = "acquired package info from nix store path"
	case pkg.Rpkg:
		answer = "acquired package info from R-package DESCRIPTION file"
	case pkg.LuaRocksPkg:
		answer = "acquired package info from Rockspec package file"
	case pkg.SwiftPkg:
		answer = "acquired package info from resolved Swift package manifest"
	case pkg.SwiplPackPkg:
		answer = "acquired package info from SWI Prolo pack package file"
	case pkg.OpamPkg:
		answer = "acquired package info from OCaml opam package file"
	case pkg.GithubActionPkg, pkg.GithubActionWorkflowPkg:
		answer = "acquired package info from GitHub Actions workflow file or composite action file"
	case pkg.WordpressPluginPkg:
		answer = "acquired package info from found wordpress plugin PHP source files"
	case pkg.HomebrewPkg:
		answer = "acquired package info from Homebrew formula"
	case pkg.TerraformPkg:
		answer = "acquired package info from Terraform dependency lock file"
	default:
		answer = "acquired package info from the following paths"
	}
	if p.FoundBy == "sbom-cataloger" {
		answer = "acquired package info from SBOM"
	}
	var paths []string
	for _, l := range p.Locations.ToSlice() {
		paths = append(paths, l.RealPath)
	}

	return answer + ": " + strings.Join(paths, ", ")
}
