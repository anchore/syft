package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_corruptDotnetPackagesLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/packages.lock.json").
		WithError().
		TestParser(t, parseDotnetPackagesLock)
}

func TestParseDotnetPackagesLock(t *testing.T) {
	fixture := "test-fixtures/packages.lock.json"
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
			From: autoMapperPkg,
			To:   extensionOptionsPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: extensionOptionsPkg,
			To:   dependencyInjectionAbstractionsPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: extensionOptionsPkg,
			To:   extensionPrimitivesPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: extensionPrimitivesPkg,
			To:   compilerServicesUnsafePkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: microsoftLoggingPkg,
			To:   extensionOptionsPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseDotnetPackagesLock, expectedPkgs, expectedRelationships)
}
