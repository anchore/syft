package dotnet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_corruptDotnetPackagesLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/glob-paths/src/packages.lock.json").
		WithError().
		TestParser(t, parseDotnetPackagesLock)
}

func TestParseDotnetPackagesLock(t *testing.T) {
	fixture := "testdata/packages.lock.json"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	autoMapperPkg := pkg.Package{
		Name:      "AutoMapper",
		Version:   "13.0.1",
		PURL:      "pkg:nuget/AutoMapper@13.0.1",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "AutoMapper",
			Version:     "13.0.1",
			ContentHash: "/Fx1SbJ16qS7dU4i604Sle+U9VLX+WSNVJggk6MupKVkYvvBm4XqYaeFuf67diHefHKHs50uQIS2YEDFhPCakQ==",
			Type:        "Direct",
		},
	}

	bootstrapPkg := pkg.Package{
		Name:      "bootstrap",
		Version:   "5.0.0",
		PURL:      "pkg:nuget/bootstrap@5.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "bootstrap",
			Version:     "5.0.0",
			ContentHash: "NKQFzFwrfWOMjTwr+X/2iJyCveuAGF+fNzkxyB0YW45+InVhcE9PUxoL1a8Vmc/Lq9E/CQd4DjO8kU32P4w/Gg==",
			Type:        "Direct",
		},
	}

	log4netPkg := pkg.Package{
		Name:      "log4net",
		Version:   "2.0.5",
		PURL:      "pkg:nuget/log4net@2.0.5",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "log4net",
			Version:     "2.0.5",
			ContentHash: "AEqPZz+v+OikfnR2SqRVdQPnSaLq5y9Iz1CfRQZ9kTKPYCXHG6zYmDHb7wJotICpDLMr/JqokyjiqKAjUKp0ng==",
			Type:        "Direct",
		},
	}

	log4net1Pkg := pkg.Package{
		Name:      "log4net",
		Version:   "1.2.15",
		PURL:      "pkg:nuget/log4net@1.2.15",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "log4net",
			Version:     "1.2.15",
			ContentHash: "KPajjkU1rbF6uY2rnakbh36LB9z9FVcYlciyOi6C5SJ3AMNywxjCGxBTN/Hl5nQEinRLuWvHWPF8W7YHh9sONw==",
			Type:        "Direct",
		},
	}

	dependencyInjectionAbstractionsPkg := pkg.Package{
		Name:      "Microsoft.Extensions.DependencyInjection.Abstractions",
		Version:   "9.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@9.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Microsoft.Extensions.DependencyInjection.Abstractions",
			Version:     "9.0.0",
			ContentHash: "xlzi2IYREJH3/m6+lUrQlujzX8wDitm4QGnUu6kUXTQAWPuZY8i+ticFJbzfqaetLA6KR/rO6Ew/HuYD+bxifg==",
			Type:        "Transitive",
		},
	}

	extensionOptionsPkg := pkg.Package{
		Name:      "Microsoft.Extensions.Options",
		Version:   "9.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Options@9.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Microsoft.Extensions.Options",
			Version:     "9.0.0",
			ContentHash: "dzXN0+V1AyjOe2xcJ86Qbo233KHuLEY0njf/P2Kw8SfJU+d45HNS2ctJdnEnrWbM9Ye2eFgaC5Mj9otRMU6IsQ==",
			Type:        "Transitive",
		},
	}

	extensionPrimitivesPkg := pkg.Package{
		Name:      "Microsoft.Extensions.Primitives",
		Version:   "9.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Primitives@9.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Microsoft.Extensions.Primitives",
			Version:     "9.0.0",
			ContentHash: "9+PnzmQFfEFNR9J2aDTfJGGupShHjOuGw4VUv+JB044biSHrnmCIMD+mJHmb2H7YryrfBEXDurxQ47gJZdCKNQ==",
			Type:        "Transitive",
		},
	}

	compilerServicesUnsafePkg := pkg.Package{
		Name:      "System.Runtime.CompilerServices.Unsafe",
		Version:   "9.0.0",
		PURL:      "pkg:nuget/System.Runtime.CompilerServices.Unsafe@9.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "System.Runtime.CompilerServices.Unsafe",
			Version:     "9.0.0",
			ContentHash: "/iUeP3tq1S0XdNNoMz5C9twLSrM/TH+qElHkXWaPvuNOt+99G75NrV0OS2EqHx5wMN7popYjpc8oTjC1y16DLg==",
			Type:        "Transitive",
		},
	}

	microsoftLoggingPkg := pkg.Package{
		Name:      "Microsoft.Extensions.Logging",
		Version:   "9.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Logging@9.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Microsoft.Extensions.Logging",
			Version:     "9.0.0",
			ContentHash: "crjWyORoug0kK7RSNJBTeSE6VX8IQgLf3nUpTB9m62bPXp/tzbnOsnbe8TXEG0AASNaKZddnpHKw7fET8E++Pg==",
			Type:        "Direct",
		},
	}

	expectedPkgs := []pkg.Package{
		autoMapperPkg,
		compilerServicesUnsafePkg,
		dependencyInjectionAbstractionsPkg,
		microsoftLoggingPkg,
		extensionOptionsPkg,
		extensionPrimitivesPkg,
		bootstrapPkg,
		log4net1Pkg,
		log4netPkg,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: extensionOptionsPkg,
			To:   autoMapperPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: dependencyInjectionAbstractionsPkg,
			To:   extensionOptionsPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: extensionPrimitivesPkg,
			To:   extensionOptionsPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: compilerServicesUnsafePkg,
			To:   extensionPrimitivesPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: extensionOptionsPkg,
			To:   microsoftLoggingPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseDotnetPackagesLock, expectedPkgs, expectedRelationships)
}

func TestParseDotnetPackagesLock_multipleTargetFrameworks(t *testing.T) {
	fixture := "testdata/packages.lock-multi-framework.json"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	myLibPkg := pkg.Package{
		Name:      "MyLib",
		Version:   "1.0.0",
		PURL:      "pkg:nuget/MyLib@1.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "MyLib",
			Version:     "1.0.0",
			ContentHash: "mylibhash==",
			Type:        "Direct",
		},
	}

	log4net2Pkg := pkg.Package{
		Name:      "log4net",
		Version:   "2.0.5",
		PURL:      "pkg:nuget/log4net@2.0.5",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "log4net",
			Version:     "2.0.5",
			ContentHash: "log4net205hash==",
			Type:        "Transitive",
		},
	}

	log4net1Pkg := pkg.Package{
		Name:      "log4net",
		Version:   "1.2.15",
		PURL:      "pkg:nuget/log4net@1.2.15",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "log4net",
			Version:     "1.2.15",
			ContentHash: "log4net1215hash==",
			Type:        "Transitive",
		},
	}

	// resolved to the same version under both frameworks (spelled "newtonsoft.json" under one), but declared "Direct" by
	// only one of them
	newtonsoftPkg := pkg.Package{
		Name:      "Newtonsoft.Json",
		Version:   "13.0.3",
		PURL:      "pkg:nuget/Newtonsoft.Json@13.0.3",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Newtonsoft.Json",
			Version:     "13.0.3",
			ContentHash: "newtonsoft1303hash==",
			Type:        "Direct",
		},
	}

	// only listed under the runtime-specific "net8.0/win-x64" section, and depends on a package from "net8.0"
	myLibNativePkg := pkg.Package{
		Name:      "runtime.win-x64.MyLib.Native",
		Version:   "1.0.0",
		PURL:      "pkg:nuget/runtime.win-x64.MyLib.Native@1.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "runtime.win-x64.MyLib.Native",
			Version:     "1.0.0",
			ContentHash: "mylibnativehash==",
			Type:        "Transitive",
		},
	}

	// only listed under "net8.0", so the "netstandard2.0" edge to it must be dropped rather than guessed
	serilogPkg := pkg.Package{
		Name:      "Serilog",
		Version:   "3.1.1",
		PURL:      "pkg:nuget/Serilog@3.1.1",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Serilog",
			Version:     "3.1.1",
			ContentHash: "serilog311hash==",
			Type:        "Transitive",
		},
	}

	expectedPkgs := []pkg.Package{
		myLibPkg,
		newtonsoftPkg,
		log4net1Pkg,
		log4net2Pkg,
		myLibNativePkg,
		serilogPkg,
	}

	// the same package is resolved to a different version per target framework, so both edges must be captured, while
	// the Newtonsoft.Json edge declared by both frameworks must appear only once
	expectedRelationships := []artifact.Relationship{
		{
			From: log4net1Pkg,
			To:   myLibPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: log4net2Pkg,
			To:   myLibPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: log4net2Pkg,
			To:   myLibNativePkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: newtonsoftPkg,
			To:   myLibPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseDotnetPackagesLock, expectedPkgs, expectedRelationships)
}

func TestParseDotnetPackagesLock_projectReference(t *testing.T) {
	fixture := "testdata/packages.lock-project-reference.json"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	newtonsoftPkg := pkg.Package{
		Name:      "Newtonsoft.Json",
		Version:   "13.0.3",
		PURL:      "pkg:nuget/Newtonsoft.Json@13.0.3",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Newtonsoft.Json",
			Version:     "13.0.3",
			ContentHash: "newtonsoft1303hash==",
			Type:        "Transitive",
		},
	}

	// a project reference has no resolved version or content hash
	myLibPkg := pkg.Package{
		Name:      "mylib",
		PURL:      "pkg:nuget/mylib",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name: "mylib",
			Type: "Project",
		},
	}

	expectedPkgs := []pkg.Package{
		newtonsoftPkg,
		myLibPkg,
	}

	// project references declare their dependencies as version ranges, which resolve to the version the target
	// framework resolved
	expectedRelationships := []artifact.Relationship{
		{
			From: newtonsoftPkg,
			To:   myLibPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseDotnetPackagesLock, expectedPkgs, expectedRelationships)
}

func Test_findPackagesLockDependency(t *testing.T) {
	frameworks := newPackagesLockFrameworks(dotnetPackagesLock{
		Dependencies: map[string]map[string]dotnetPackagesLockDep{
			"net8.0": {
				"log4net": {Resolved: "2.0.5"},
			},
			"net8.0/win-x64": {
				"runtime.win-x64.Native": {Resolved: "1.0.0"},
			},
			"netstandard2.0": {
				"log4net":         {Resolved: "1.2.15"},
				"Newtonsoft.Json": {Resolved: "13.0.3"},
			},
		},
	})
	net8, rid, netstandard := frameworks[0], frameworks[1], frameworks[2]

	tests := []struct {
		name        string
		depName     string
		framework   packagesLockFramework
		base        packagesLockFramework
		wantVersion string
		wantFound   bool
	}{
		{
			name:        "resolves to the version pinned by its own target framework",
			depName:     "log4net",
			framework:   netstandard,
			wantVersion: "1.2.15",
			wantFound:   true,
		},
		{
			name:        "package names are matched case-insensitively",
			depName:     "LOG4NET",
			framework:   net8,
			wantVersion: "2.0.5",
			wantFound:   true,
		},
		{
			name:        "runtime-specific sections fall back to their base target framework",
			depName:     "log4net",
			framework:   rid,
			base:        net8,
			wantVersion: "2.0.5",
			wantFound:   true,
		},
		{
			name:      "a package absent from the target framework is not guessed from another one",
			depName:   "Newtonsoft.Json",
			framework: net8,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := findPackagesLockDependency(tt.depName, tt.framework, tt.base)
			require.Equal(t, tt.wantFound, found)
			if !tt.wantFound {
				return
			}
			assert.Equal(t, tt.wantVersion, got.dep.Resolved)
		})
	}
}

func Test_mergePackagesLockEntries_typePrecedence(t *testing.T) {
	tests := []struct {
		name     string
		types    map[string]string // target framework -> type
		wantType string
	}{
		{
			name:     "direct wins over transitive",
			types:    map[string]string{"net8.0": "Transitive", "netstandard2.0": "Direct"},
			wantType: "Direct",
		},
		{
			name:     "central transitive wins over transitive regardless of framework order",
			types:    map[string]string{"net8.0": "Transitive", "netstandard2.0": "CentralTransitive"},
			wantType: "CentralTransitive",
		},
		{
			name:     "central transitive wins over transitive in the reverse framework order",
			types:    map[string]string{"net8.0": "CentralTransitive", "netstandard2.0": "Transitive"},
			wantType: "CentralTransitive",
		},
		{
			name:     "direct wins over central transitive",
			types:    map[string]string{"net472": "CentralTransitive", "net8.0": "Direct", "netstandard2.0": "Transitive"},
			wantType: "Direct",
		},
		{
			name:     "known types win over unknown ones",
			types:    map[string]string{"net8.0": "Unknown", "netstandard2.0": "Transitive"},
			wantType: "Transitive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockFile := dotnetPackagesLock{Dependencies: map[string]map[string]dotnetPackagesLockDep{}}
			for framework, depType := range tt.types {
				lockFile.Dependencies[framework] = map[string]dotnetPackagesLockDep{
					"Newtonsoft.Json": {Type: depType, Resolved: "13.0.3"},
				}
			}

			entries := mergePackagesLockEntries(newPackagesLockFrameworks(lockFile))
			require.Len(t, entries, 1)
			assert.Equal(t, tt.wantType, entries[0].dep.Type)
		})
	}
}
