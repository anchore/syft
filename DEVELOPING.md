# Developing

## Getting started

In order to test and develop in this repo you will need the following dependencies installed:
- Golang
- docker
- make

After cloning the following step can help you get setup:
1. run `make bootstrap` to download go mod dependencies, create the `/.tmp` dir, and download helper utilities.
2. run `make` to view the selection of developer commands in the Makefile
3. run `make build` to build the release snapshot binaries and packages
4. for an even quicker start you can run `go run cmd/syft/main.go` to print the syft help.
	- this command `go run cmd/syft/main.go alpine:latest` will compile and run syft against `alpine:latest`
5. view the README or syft help output for more output options

The main make tasks for common static analysis and testing are `lint`, `lint-fix`, `unit`, `integration`, and `cli`.

See `make help` for all the current make tasks.

## Architecture

Syft is used to generate a Software Bill of Materials (SBOM) from different kinds of input.

### Code organization for the cmd package

Syft's entrypoint can be found in the `cmd` package at `cmd/syft/main.go`. `main.go` builds a new syft `cli` via `cli.New()` 
and then executes the `cli` via `cli.Execute()`. The `cli` package is responsible for parsing command line arguments, 
setting up the application context and configuration, and executing the application. Each of syft's commands 
(e.g. `packages`, `attest`, `version`) are implemented as a `cobra.Command` in their respective `<command>.go` files. 
They are registered in `syft/cli/commands/go`.
```
.
└── syft/
    ├── cli/
    │   ├── attest/
    │   ├── attest.go
    │   ├── commands.go
    │   ├── completion.go
    │   ├── convert/
    │   ├── convert.go
    │   ├── eventloop/
    │   ├── options/
    │   ├── packages/
    │   ├── packages.go
    │   ├── poweruser/
    │   ├── poweruser.go
    │   └── version.go
    └── main.go
```

#### Execution flow

```mermaid
sequenceDiagram
    participant main as cmd/syft/main
    participant cli as cli.New()
    participant root as root.Execute()
    participant cmd as <command>.Execute()

    main->>+cli: 

    Note right of cli: wire ALL CLI commands
    Note right of cli: add flags for ALL commands

    cli-->>-main:  root command 

    main->>+root: 
    root->>+cmd: 
    cmd-->>-root: (error)  

    root-->>-main: (error) 

    Note right of cmd: Execute SINGLE command from USER
```

### Code organization for syft library

Syft's core library (see, exported) functionality is implemented in the `syft` package. The `syft` package is responsible for organizing the core
SBOM data model, it's translated output formats, and the core SBOM generation logic.

- analysis creates a static SBOM which can be encoded and decoded
- format objects, should strive to not add or enrich data in encoding that could otherwise be done during analysis
- package catalogers and their organization can be viewed/added to the `syft/pkg/cataloger` package 
- file catalogers and their organization can be viewed/added to the `syft/file` package
- The source package provides an abstraction to allow a user to loosely define a data source that can be cataloged

#### Code example of syft as a library

Here is a gist of using syft as a library to generate a SBOM for a docker image: [link](https://gist.github.com/wagoodman/57ed59a6d57600c23913071b8470175b).
The execution flow for the example is detailed below.

#### Execution flow examples for the syft library

```mermaid
sequenceDiagram
    participant source as source.New(ubuntu:latest)
    participant sbom as sbom.SBOM
    participant catalog as syft.CatalogPackages(src)
    participant encoder as syft.Encode(sbom, format)

    Note right of source: use "ubuntu:latest" as SBOM input

    source-->>+sbom: add source to SBOM struct
    source-->>+catalog: pass src to generate catalog
    catalog-->-sbom: add cataloging results onto SBOM
    sbom-->>encoder: pass SBOM and format desiered to syft encoder
    encoder-->>source: return bytes that are the SBOM of the original input 

    Note right of catalog: cataloger configuration is done based on src
```


### Syft Catalogers

##### Summary

Catalogers are the way in which syft is able to identify and construct packages given some amount of source metadata.
For example, Syft can locate and process `package-lock.json` files when performing filesystem scans. 
See: [how to specify file globs](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger/javascript/cataloger.go#L16-L21)
and an implementation of the [package-lock.json parser](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger/javascript/cataloger.go#L16-L21) for a quick review.

From a high level catalogers have the following properties:

- They are independent from one another. The java cataloger has no idea of the processes, assumptions, or results of the python cataloger, for example.

- They do not know what source is being analyzed. Are we analyzing a local directory? an image? if so, the squashed representation or all layers? The catalogers do not know the answers to these questions. Only that there is an interface to query for file paths and contents from an underlying "source" being scanned.

- Packages created by the cataloger should not be mutated after they are created. There is one exception made for adding CPEs to a package after the cataloging phase, but that will most likely be moved back into the cataloger in the future.

#### Building a new Cataloger

Catalogers must fulfill the interface [found here](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger.go). 
This means that when building a new cataloger, the new struct must implement both method signatures of `Catalog` and `Name`.

A top level view of the functions that construct all the catalogers can be found [here](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger/cataloger.go).
When an author has finished writing a new cataloger this is the spot to plug in the new catalog constructor.

For a top level view of how the catalogers are used see [this function](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger/catalog.go#L41-L100) as a reference. It ranges over all catalogers passed as an argument and invokes the `Catalog` method:

Each cataloger has its own `Catalog` method, but this does not mean that they are all vastly different.
Take a look at the `apkdb` cataloger for alpine to see how it [constructs a generic.NewCataloger](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger/apkdb/cataloger.go).

`generic.NewCataloger` is an abstraction syft uses to make writing common components easier. First, it takes the `catalogerName` to identify the cataloger.
On the other side of the call it uses two key pieces which inform the cataloger how to identify and return packages, the `globPatterns` and the `parseFunction`:
- The first piece is a `parseByGlob` matching pattern used to identify the files that contain the package metadata.
See [here for the APK example](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/apk_metadata.go#L16-L41).
- The other is a `parseFunction` which informs the cataloger what to do when it has found one of the above matches files.
See this [link for an example](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger/apkdb/parse_apk_db.go#L22-L102).

If you're unsure about using the `Generic Cataloger` and think the use case being filled requires something more custom
just file an issue or ask in our slack, and we'd be more than happy to help on the design.

Identified packages share a common struct so be sure that when the new cataloger is constructing a new package it is using the [`Package` struct](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/package.go#L16-L31).

Metadata Note: Identified packages are also assigned specific metadata that can be unique to their environment. 
See [this folder](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg) for examples of the different metadata types.
These are plugged into the `MetadataType` and `Metadata` fields in the above struct. `MetadataType` informs which type is being used. `Metadata` is an interface converted to that type.

Finally, here is an example of where the package construction is done in the apk cataloger. The first link is where `newPackage` is called in the `parseFunction`. The second link shows the package construction:
- [Call for new package](https://github.com/anchore/syft/blob/v0.70.0/syft/pkg/cataloger/apkdb/parse_apk_db.go#L106)
- [APK Package Constructor](https://github.com/anchore/syft/tree/v0.70.0/syft/pkg/cataloger/apkdb/package.go#L12-L27)

If you have more questions about implementing a cataloger or questions about one you might be currently working
always feel free to file an issue or reach out to us [on slack](https://anchore.com/slack).

#### Searching for files

All catalogers are provided an instance of the [`source.FileResolver`](https://github.com/anchore/syft/blob/v0.70.0/syft/source/file_resolver.go#L8) to interface with the image and search for files. The implementations for these 
abstractions leverage [`stereoscope`](https://github.com/anchore/stereoscope) in order to perform searching. Here is a 
rough outline how that works:

1. a stereoscope `file.Index` is searched based on the input given (a path, glob, or MIME type). The index is relatively fast to search, but requires results to be filtered down to the files that exist in the specific layer(s) of interest. This is done automatically by the `filetree.Searcher` abstraction. This abstraction will fallback to searching directly against the raw `filetree.FileTree` if the index does not contain the file(s) of interest. Note: the `filetree.Searcher` is used by the `source.FileResolver` abstraction.
2. Once the set of files are returned from the `filetree.Searcher` the results are filtered down further to return the most unique file results. For example, you may have requested for files by a glob that returns multiple results. These results are filtered down to deduplicate by real files, so if a result contains two references to the same file, say one accessed via symlink and one accessed via the real path, then the real path reference is returned and the symlink reference is filtered out. If both were accessed by symlink then the first (by lexical order) is returned. This is done automatically by the `source.FileResolver` abstraction.
3. By the time results reach the `pkg.Cataloger` you are guaranteed to have a set of unique files that exist in the layer(s) of interest (relative to what the resolver supports).

## Testing

### Levels of testing

- `unit`: The default level of test which is distributed throughout the repo are unit tests. Any `_test.go` file that 
  does not reside somewhere within the `/test` directory is a unit test. Other forms of testing should be organized in 
  the `/test` directory. These tests should focus on correctness of functionality in depth. % test coverage metrics 
  only considers unit tests and no other forms of testing.

- `integration`: located within `test/integration`, these tests focus on the behavior surfaced by the common library 
  entrypoints from the `syft` package and make light assertions about the results surfaced. Additionally, these tests
  tend to make diversity assertions for enum-like objects, ensuring that as enum values are added to a definition
  that integration tests will automatically fail if no test attempts to use that enum value. For more details see 
  the "Data diversity and freshness assertions" section below.

- `cli`: located with in `test/cli`, these are tests that test the correctness of application behavior from a 
  snapshot build. This should be used in cases where a unit or integration test will not do or if you are looking
  for in-depth testing of code in the `cmd/` package (such as testing the proper behavior of application configuration,
  CLI switches, and glue code before syft library calls).

- `acceptance`: located within `test/compare` and `test/install`, these are smoke-like tests that ensure that application  
  packaging and installation works as expected. For example, during release we provide RPM packages as a download 
  artifact. We also have an accompanying RPM acceptance test that installs the RPM from a snapshot build and ensures the 
  output of a syft invocation matches canned expected output. New acceptance tests should be added for each release artifact
  and architecture supported (when possible).

### Data diversity and freshness assertions

It is important that tests against the codebase are flexible enough to begin failing when they do not cover "enough"
of the objects under test. "Cover" in this case does not mean that some percentage of the code has been executed 
during testing, but instead that there is enough diversity of data input reflected in testing relative to the
definitions available.

For instance, consider an enum-like value like so:
```go
type Language string

const (
  Java            Language = "java"
  JavaScript      Language = "javascript"
  Python          Language = "python"
  Ruby            Language = "ruby"
  Go              Language = "go"
)
```

Say we have a test that exercises all the languages defined today:

```go
func TestCatalogPackages(t *testing.T) {
  testTable := []struct {
    // ... the set of test cases that test all languages
  }
  for _, test := range cases {
    t.Run(test.name, func (t *testing.T) {
      // use inputFixturePath and assert that syft.CatalogPackages() returns the set of expected Package objects
      // ...
    })
  }
}
```

Where each test case has a `inputFixturePath` that would result with packages from each language. This test is
brittle since it does not assert that all languages were exercised directly and future modifications (such as 
adding a new language) won't be covered by any test cases.

To address this the enum-like object should have a definition of all objects that can be used in testing:

```go
type Language string

// const( Java Language = ..., ... )

var AllLanguages = []Language{
	Java,
	JavaScript,
	Python,
	Ruby,
	Go,
	Rust,
}
```

Allowing testing to automatically fail when adding a new language:

```go
func TestCatalogPackages(t *testing.T) {
  testTable := []struct {
  	// ... the set of test cases that (hopefully) covers all languages
  }

  // new stuff...
  observedLanguages := strset.New()
  
  for _, test := range cases {
    t.Run(test.name, func (t *testing.T) {
      // use inputFixturePath and assert that syft.CatalogPackages() returns the set of expected Package objects
    	// ...
    	
    	// new stuff...
    	for _, actualPkg := range actual {
        observedLanguages.Add(string(actualPkg.Language))
    	}
    	
    })
  }

   // new stuff...
  for _, expectedLanguage := range pkg.AllLanguages {
    if 	!observedLanguages.Contains(expectedLanguage) {
      t.Errorf("failed to test language=%q", expectedLanguage)	
    }
  }
}
```

This is a better test since it will fail when someone adds a new language but fails to write a test case that should
exercise that new language. This method is ideal for integration-level testing, where testing correctness in depth 
is not needed (that is what unit tests are for) but instead testing in breadth to ensure that units are well integrated.

A similar case can be made for data freshness; if the quality of the results will be diminished if the input data
is not kept up to date then a test should be written (when possible) to assert any input data is not stale.

An example of this is the static list of licenses that is stored in `internal/spdxlicense` for use by the SPDX 
presenters. This list is updated and published periodically by an external group and syft can grab and update this
list by running `go generate ./...` from the root of the repo.

An integration test has been written to grabs the latest license list version externally and compares that version
with the version generated in the codebase. If they differ, the test fails, indicating to someone that there is an
action needed to update it.

**_The key takeaway is to try and write tests that fail when data assumptions change and not just when code changes.**_

### Snapshot tests

The format objects make a lot of use of "snapshot" testing, where you save the expected output bytes from a call into the
git repository and during testing make a comparison of the actual bytes from the subject under test with the golden
copy saved in the repo. The "golden" files are stored in the `test-fixtures/snapshot` directory relative to the go 
package under test and should always be updated by invoking `go test` on the specific test file with a specific CLI 
update flag provided.

Many of the `Format` tests make use of this approach, where the raw SBOM report is saved in the repo and the test 
compares that SBOM with what is generated from the latest presenter code. For instance, at the time of this writing 
the CycloneDX presenter snapshots can be updated by running:

```bash
go test ./internal/formats -update-cyclonedx
```

These flags are defined at the top of the test files that have tests that use the snapshot files.

Snapshot testing is only as good as the manual verification of the golden snapshot file saved to the repo! Be careful 
and diligent when updating these files.


