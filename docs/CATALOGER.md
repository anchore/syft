# Syft Catalogers

## Summary
Catalogers are the way in which syft is able to identify and construct packages given some amount of source metadata. 
For example, syft can use a `package.json` file in conjunction with a `package-lock.json` file to build a list of javascript packages based on the joining metadata:
- [Cataloger Construction](https://github.com/anchore/syft/blob/e3d6ffd30e44428b898675922a0474221a7f7dc7/syft/pkg/cataloger/javascript/cataloger.go#L16-L21)
- [Package Lock Parsing](https://github.com/anchore/syft/blob/e3d6ffd30e44428b898675922a0474221a7f7dc7/syft/pkg/cataloger/javascript/parse_package_lock.go#L43-L90)

### Building a new Cataloger
Catalogers must fulfill the interface found here. This means that when building a new cataloger, the new struct must implement both method signatures of `Catalog` and `Name`:
- [Cataloger Interface](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger.go)

A top level view of the functions that construct all the catalogers can be found here. When an author has finished writing a new cataloger this is where it will be plugged in:
- [Cataloger Constructors](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/cataloger.go)

For a top level view of how the catalogers are used see this function as a reference. It ranges over all catalogers passed as an argument and invokes the `Catalog` method:
- [Syft using the catalogers](https://github.com/anchore/syft/blob/6a7d6e6071829c7ce2943266c0e187b27c0b325c/syft/pkg/cataloger/catalog.go#L41-L100)

Each cataloger has its own `Catalog` method, but this does not mean that they are all vastly different.
Take a look at the `apkdb` cataloger for alpine to see how it constructs a generic.NewCataloger:
- [APKDB Cataloger Construction](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/apkdb/cataloger.go)

`generic.NewCataloger` is an abstraction syft uses to make writing common components easier. First, it takes the `catalogerName` to identify the cataloger.
On the other side of the call it uses two key pieces which inform the cataloger how to identify and return packages, the `globPatterns` and the `parseFunction`:
- One is a `parseByGlob` matching pattern used to identify the files that contain the package metadata. See here for the APK example:
	- [Parse By Glob APK Example](https://github.com/anchore/syft/blob/1ae577a0351fca4aa29bb04e73888aca973d73e0/syft/pkg/apk_metadata.go#L16-L41)
- The other is a `parseFunction` which informs the cataloger what to do when it has found one of the above files:
	- [APK Parse Function Example](https://github.com/anchore/syft/blob/6a7d6e6071829c7ce2943266c0e187b27c0b325c/syft/pkg/cataloger/apkdb/parse_apk_db.go#L22-L102)

If you're unsure about using the `Generic Cataloger` and think the use case being filled requires something more custom
just file an issue or ask in our slack, and we'd be more than happy to help on the design.

Identified packages share a common struct so be sure that when constructing a new cataloger to be aware of the `Package` struct:
- [Package](https://github.com/anchore/syft/blob/e3d6ffd30e44428b898675922a0474221a7f7dc7/syft/pkg/package.go#L16-L31)

Note: Identified packages are also assigned specific metadata that can be unique to their environment. 
See this folder for examples of the different metadata types.
These are plugged into the `MetadataType` and `Metadata` fields in the above struct. `MetadataType` informs which type is being used. `Metadata` is an interface converted to that type.
- [Metadata Examples](https://github.com/anchore/syft/tree/main/syft/pkg)

Here is an example of where the package construction is done in the apk cataloger. The first link is where `newPackage` is called in the `parseFunction`. The second link shows the package construction:
- [Call for new package](https://github.com/anchore/syft/blob/6a7d6e6071829c7ce2943266c0e187b27c0b325c/syft/pkg/cataloger/apkdb/parse_apk_db.go#L96-L99)
- [APK Package Constructor](https://github.com/anchore/syft/blob/6a7d6e6071829c7ce2943266c0e187b27c0b325c/syft/pkg/cataloger/apkdb/package.go#L12-L27)