<p align="center">
    <img src="https://user-images.githubusercontent.com/5199289/136844524-1527b09f-c5cb-4aa9-be54-5aa92a6086c1.png" width="271" alt="Cute pink owl syft logo">
</p>

[![Validations](https://github.com/anchore/syft/actions/workflows/validations.yaml/badge.svg)](https://github.com/anchore/syft/actions/workflows/validations.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/anchore/syft)](https://goreportcard.com/report/github.com/anchore/syft)
[![GitHub release](https://img.shields.io/github/release/anchore/syft.svg)](https://github.com/anchore/syft/releases/latest)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/anchore/syft.svg)](https://github.com/anchore/syft)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/syft/blob/main/LICENSE)
[![Slack Invite](https://img.shields.io/badge/Slack-Join-blue?logo=slack)](https://anchore.com/slack)

A CLI tool and Go library for generating a Software Bill of Materials (SBOM) from container images and filesystems. Exceptional for vulnerability detection when used with a scanner like [Grype](https://github.com/anchore/grype).

### Join our community meetings!

- Calendar: https://calendar.google.com/calendar/u/0/r?cid=Y182OTM4dGt0MjRtajI0NnNzOThiaGtnM29qNEBncm91cC5jYWxlbmRhci5nb29nbGUuY29t
- Agenda: https://docs.google.com/document/d/1ZtSAa6fj2a6KRWviTn3WoJm09edvrNUp4Iz_dOjjyY8/edit?usp=sharing (join [this group](https://groups.google.com/g/anchore-oss-community) for write access)
- All are welcome!

For commercial support options with Syft or Grype, please [contact Anchore](https://get.anchore.com/contact/)

![syft-demo](https://user-images.githubusercontent.com/590471/90277200-2a253000-de33-11ea-893f-32c219eea11a.gif)

## Features
- Generates SBOMs for container images, filesystems, archives, and more to discover packages and libraries
- Supports OCI, Docker and [Singularity](https://github.com/sylabs/singularity) image formats
- Linux distribution identification
- Works seamlessly with [Grype](https://github.com/anchore/grype) (a fast, modern vulnerability scanner)
- Able to create signed SBOM attestations using the [in-toto specification](https://github.com/in-toto/attestation/blob/main/spec/README.md)
- Convert between SBOM formats, such as CycloneDX, SPDX, and Syft's own format.

### Supported Ecosystems

- Alpine (apk)
- C (conan)
- C++ (conan)
- Dart (pubs)
- Debian (dpkg)
- Dotnet (deps.json)
- Objective-C (cocoapods)
- Elixir (mix)
- Erlang (rebar3)
- Go (go.mod, Go binaries)
- Haskell (cabal, stack)
- Java (jar, ear, war, par, sar, nar, native-image)
- JavaScript (npm, yarn)
- Jenkins Plugins (jpi, hpi)
- Linux kernel archives (vmlinz)
- Linux kernel modules (ko)
- Nix (outputs in /nix/store)
- PHP (composer)
- Python (wheel, egg, poetry, requirements.txt)
- Red Hat (rpm)
- Ruby (gem)
- Rust (cargo.lock)
- Swift (cocoapods, swift-package-manager)

## Installation

**Note**: Currently, Syft is built only for Linux, macOS and Windows.

### Recommended
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

### Chocolatey

The chocolatey distribution of syft is community maintained and not distributed by the anchore team

```powershell
choco install syft -y
```

### Scoop

```powershell
scoop install syft
```

### Homebrew
```bash
brew install syft
```

### Nix

**Note**: Nix packaging of Syft is [community maintained](https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/admin/syft/default.nix). Syft is available in the [stable channel](https://nixos.wiki/wiki/Nix_channels#The_official_channels) since NixOS `22.05`.

```bash
nix-env -i syft
```

... or, just try it out in an ephemeral nix shell:

```bash
nix-shell -p syft
```

## Getting started

### SBOM

To generate an SBOM for a container image:

```
syft <image>
```

The above output includes only software that is visible in the container (i.e., the squashed representation of the image). To include software from all image layers in the SBOM, regardless of its presence in the final image, provide `--scope all-layers`:

```
syft <image> --scope all-layers
```

### Supported sources

Syft can generate a SBOM from a variety of sources:

```
# catalog a container image archive (from the result of `docker image save ...`, `podman save ...`, or `skopeo copy` commands)
syft path/to/image.tar

# catalog a Singularity Image Format (SIF) container
syft path/to/image.sif

# catalog a directory
syft path/to/dir
```

Sources can be explicitly provided with a scheme:

```
docker:yourrepo/yourimage:tag            use images from the Docker daemon
podman:yourrepo/yourimage:tag            use images from the Podman daemon
containerd:yourrepo/yourimage:tag        use images from the Containerd daemon
docker-archive:path/to/yourimage.tar     use a tarball from disk for archives created from "docker save"
oci-archive:path/to/yourimage.tar        use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir:path/to/yourimage                read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
singularity:path/to/yourimage.sif        read directly from a Singularity Image Format (SIF) container on disk
dir:path/to/yourproject                  read directly from a path on disk (any directory)
file:path/to/yourproject/file            read directly from a path on disk (any single file)
registry:yourrepo/yourimage:tag          pull image directly from a registry (no container runtime required)
```

If an image source is not provided and cannot be detected from the given reference it is assumed the image should be pulled from the Docker daemon.
If docker is not present, then the Podman daemon is attempted next, followed by reaching out directly to the image registry last.


This default behavior can be overridden with the `default-image-pull-source` configuration option (See [Configuration](https://github.com/anchore/syft#configuration) for more details).

### Default Cataloger Configuration by scan type

Syft uses different default sets of catalogers depending on what it is scanning: a container image or a directory on disk. The default catalogers for an image scan assumes that package installation steps have already been completed. For example, Syft will identify Python packages that have egg or wheel metadata files under a site-packages directory, since this indicates software actually installed on an image.

However, if you are scanning a directory, Syft doesn't assume that all relevant software is installed, and will use catalogers that can identify declared dependencies that may not yet be installed on the final system: for example, dependencies listed in a Python requirements.txt.

You can override the list of enabled/disabled catalogers by using the "catalogers" keyword in the [Syft configuration file](https://github.com/anchore/syft#configuration).

##### Image Scanning:
- alpmdb
- apkdb
- binary
- dotnet-deps
- dpkgdb
- go-module-binary
- graalvm-native-image
- java
- javascript-package
- linux-kernel
- nix-store
- php-composer-installed
- portage
- python-package
- rpm-db
- ruby-gemspec
- sbom

##### Directory Scanning:
- alpmdb
- apkdb
- binary
- cocoapods
- conan
- dartlang-lock
- dotnet-deps
- dpkgdb
- elixir-mix-lock
- erlang-rebar-lock
- go-mod-file
- go-module-binary
- graalvm-native-image
- haskell
- java
- java-gradle-lockfile
- java-pom
- javascript-lock
- linux-kernel
- nix-store
- php-composer-lock
- portage
- python-index
- python-package
- rpm-db
- rpm-file
- ruby-gemfile
- rust-cargo-lock
- sbom
- swift-package-manager

##### Non Default:
- cargo-auditable-binary

### Excluding file paths

Syft can exclude files and paths from being scanned within a source by using glob expressions
with one or more `--exclude` parameters:
```
syft <source> --exclude './out/**/*.json' --exclude /etc
```
**Note:** in the case of _image scanning_, since the entire filesystem is scanned it is
possible to use absolute paths like `/etc` or `/usr/**/*.txt` whereas _directory scans_
exclude files _relative to the specified directory_. For example: scanning `/usr/foo` with
`--exclude ./package.json` would exclude `/usr/foo/package.json` and `--exclude '**/package.json'`
would exclude all `package.json` files under `/usr/foo`. For _directory scans_,
it is required to begin path expressions with `./`, `*/`, or `**/`, all of which
will be resolved _relative to the specified scan directory_. Keep in mind, your shell
may attempt to expand wildcards, so put those parameters in single quotes, like:
`'**/*.json'`.

### Output formats

The output format for Syft is configurable as well using the
`-o` (or `--output`) option:

```
syft <image> -o <format>
```

Where the `formats` available are:
- `json`: Use this to get as much information out of Syft as possible!
- `text`: A row-oriented, human-and-machine-friendly output.
- `cyclonedx-xml`: A XML report conforming to the [CycloneDX 1.4 specification](https://cyclonedx.org/specification/overview/).
- `cyclonedx-json`: A JSON report conforming to the [CycloneDX 1.4 specification](https://cyclonedx.org/specification/overview/).
- `spdx-tag-value`: A tag-value formatted report conforming to the [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/).
- `spdx-tag-value@2.2`: A tag-value formatted report conforming to the [SPDX 2.2 specification](https://spdx.github.io/spdx-spec/v2.2.2/).
- `spdx-json`: A JSON report conforming to the [SPDX 2.3 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json).
- `spdx-json@2.2`: A JSON report conforming to the [SPDX 2.2 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.2/schemas/spdx-schema.json).
- `github`: A JSON report conforming to GitHub's dependency snapshot format.
- `table`: A columnar summary (default).
- `template`: Lets the user specify the output format. See ["Using templates"](#using-templates) below.

## Using templates

Syft lets you define custom output formats, using [Go templates](https://pkg.go.dev/text/template). Here's how it works:

- Define your format as a Go template, and save this template as a file.

- Set the output format to "template" (`-o template`).

- Specify the path to the template file (`-t ./path/to/custom.template`).

- Syft's template processing uses the same data models as the `json` output format — so if you're wondering what data is available as you author a template, you can use the output from `syft <image> -o json` as a reference.

**Example:** You could make Syft output data in CSV format by writing a Go template that renders CSV data and then running `syft <image> -o template -t ~/path/to/csv.tmpl`.

Here's what the `csv.tmpl` file might look like:
```gotemplate
"Package","Version Installed","Found by"
{{- range .Artifacts}}
"{{.Name}}","{{.Version}}","{{.FoundBy}}"
{{- end}}
```

Which would produce output like:
```text
"Package","Version Installed","Found by"
"alpine-baselayout","3.2.0-r20","apkdb-cataloger"
"alpine-baselayout-data","3.2.0-r20","apkdb-cataloger"
"alpine-keys","2.4-r1","apkdb-cataloger"
...
```

Syft also includes a vast array of utility templating functions from [sprig](http://masterminds.github.io/sprig/) apart from the default Golang [text/template](https://pkg.go.dev/text/template#hdr-Functions) to allow users to customize the output format.

Lastly, Syft has custom templating functions defined in `./syft/format/template/encoder.go` to help parse the passed-in JSON structs.

## Multiple outputs

Syft can also output _multiple_ files in differing formats by appending
`=<file>` to the option, for example to output Syft JSON and SPDX JSON:

```shell
syft <image> -o json=sbom.syft.json -o spdx-json=sbom.spdx.json
```

## Private Registry Authentication

### Local Docker Credentials
When a container runtime is not present, Syft can still utilize credentials configured in common credential sources (such as `~/.docker/config.json`). It will pull images from private registries using these credentials. The config file is where your credentials are stored when authenticating with private registries via some command like `docker login`. For more information see the `go-containerregistry` [documentation](https://github.com/google/go-containerregistry/tree/main/pkg/authn).

An example `config.json` looks something like this:
```json
{
	"auths": {
		"registry.example.com": {
			"username": "AzureDiamond",
			"password": "hunter2"
		}
	}
}
```

You can run the following command as an example. It details the mount/environment configuration a container needs to access a private registry:

```
docker run -v ./config.json:/config/config.json -e "DOCKER_CONFIG=/config" anchore/syft:latest  <private_image>
```

### Docker Credentials in Kubernetes

Here's a simple workflow to mount this config file as a secret into a container on Kubernetes.

1. Create a secret. The value of `config.json` is important. It refers to the specification detailed [here](https://github.com/google/go-containerregistry/tree/main/pkg/authn#the-config-file). Below this section is the `secret.yaml` file that the pod configuration will consume as a volume. The key `config.json` is important. It will end up being the name of the file when mounted into the pod.

    ```yaml
    # secret.yaml

    apiVersion: v1
    kind: Secret
    metadata:
      name: registry-config
      namespace: syft
    data:
      config.json: <base64 encoded config.json>
    ```

   `kubectl apply -f secret.yaml`


2. Create your pod running syft. The env `DOCKER_CONFIG` is important because it advertises where to look for the credential file. In the below example, setting `DOCKER_CONFIG=/config` informs syft that credentials can be found at `/config/config.json`. This is why we used `config.json` as the key for our secret. When mounted into containers the secrets' key is used as the filename. The `volumeMounts` section mounts our secret to `/config`. The `volumes` section names our volume and leverages the secret we created in step one.

    ```yaml
    # pod.yaml

    apiVersion: v1
    kind: Pod
    metadata:
      name: syft-k8s-usage
    spec:
      containers:
        - image: anchore/syft:latest
          name: syft-private-registry-demo
          env:
            - name: DOCKER_CONFIG
              value: /config
          volumeMounts:
          - mountPath: /config
            name: registry-config
            readOnly: true
          args:
            - <private_image>
      volumes:
      - name: registry-config
        secret:
          secretName: registry-config
    ```

   `kubectl apply -f pod.yaml`


3. The user can now run `kubectl logs syft-private-registry-demo`. The logs should show the Syft analysis for the `<private_image>` provided in the pod configuration.

Using the above information, users should be able to configure private registry access without having to do so in the `grype` or `syft` configuration files.  They will also not be dependent on a Docker daemon, (or some other runtime software) for registry configuration and access.

## Format conversion (experimental)

The ability to convert existing SBOMs means you can create SBOMs in different formats quickly, without the need to regenerate the SBOM from scratch, which may take significantly more time.

```
syft convert <ORIGINAL-SBOM-FILE> -o <NEW-SBOM-FORMAT>[=<NEW-SBOM-FILE>]
```

This feature is experimental and data might be lost when converting formats. Packages are the main SBOM component easily transferable across formats, whereas files and relationships, as well as other information Syft doesn't support, are more likely to be lost.

We support formats with wide community usage AND good encode/decode support by Syft. The supported formats are:
- Syft JSON (```-o syft-json```)
- SPDX 2.2 JSON (```-o spdx-json```)
- SPDX 2.2 tag-value (```-o spdx-tag-value```)
- CycloneDX 1.4 JSON (```-o cyclonedx-json```)
- CycloneDX 1.4 XML (```-o cyclonedx-xml```)

Conversion example:
```sh
syft alpine:latest -o syft-json=sbom.syft.json # generate a syft SBOM
syft convert sbom.syft.json -o cyclonedx-json=sbom.cdx.json  # convert it to CycloneDX
```

## Attestation (experimental)
### Keyless support
Syft supports generating attestations using cosign's [keyless](https://github.com/sigstore/cosign/blob/main/KEYLESS.md) signatures.

Note: users need to have >= v1.12.0 of cosign installed for this command to function

To use this feature with a format like CycloneDX json simply run:
```
syft attest --output cyclonedx-json <IMAGE WITH OCI WRITE ACCESS>
```
This command will open a web browser and allow the user to authenticate their OIDC identity as the root of trust for the attestation (Github, Google, Microsoft).

After authenticating, Syft will upload the attestation to the OCI registry specified by the image that the user has write access to.

You will need to make sure your credentials are configured for the OCI registry you are uploading to so that the attestation can write successfully.

Users can then verify the attestation(or any image with attestations) by running:
```
COSIGN_EXPERIMENTAL=1 cosign verify-attestation <IMAGE_WITH_ATTESTATIONS>
```

Users should see that the uploaded attestation claims are validated, the claims exist within the transparency log, and certificates on the attestations were verified against [fulcio](https://github.com/SigStore/fulcio).
There will also be a printout of the certificates subject `<user identity>` and the certificate issuer URL: `<provider of user identity (Github, Google, Microsoft)>`:
```
Certificate subject:  test.email@testdomain.com
Certificate issuer URL:  https://accounts.google.com
```

### Local private key support

To generate an SBOM attestation for a container image using a local private key:
```
syft attest --output [FORMAT] --key [KEY] [SOURCE] [flags]
```

The above output is in the form of the [DSSE envelope](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md#dsse-envelope).
The payload is a base64 encoded `in-toto` statement with the generated SBOM as the predicate. For details on workflows using this command see [here](#adding-an-sbom-to-an-image-as-an-attestation-using-syft).



## Configuration

Configuration search paths:

- `.syft.yaml`
- `.syft/config.yaml`
- `~/.syft.yaml`
- `<XDG_CONFIG_HOME>/syft/config.yaml`

Configuration options (example values are the default):

```yaml
# the output format(s) of the SBOM report (options: table, text, json, spdx, ...)
# same as -o, --output, and SYFT_OUTPUT env var
# to specify multiple output files in differing formats, use a list:
# output:
#   - "json=<syft-json-output-file>"
#   - "spdx-json=<spdx-json-output-file>"
output: "table"

# suppress all output (except for the SBOM report)
# same as -q ; SYFT_QUIET env var
quiet: false

# same as --file; write output report to a file (default is to write to stdout)
file: ""

# enable/disable checking for application updates on startup
# same as SYFT_CHECK_FOR_APP_UPDATE env var
check-for-app-update: true

# allows users to specify which image source should be used to generate the sbom
# valid values are: registry, docker, podman
default-image-pull-source: ""

# a list of globs to exclude from scanning. same as --exclude ; for example:
# exclude:
#   - "/etc/**"
#   - "./out/**/*.json"
exclude: []

# allows users to exclude synthetic binary packages from the sbom
# these packages are removed if an overlap with a non-synthetic package is found
exclude-binary-overlap-by-ownership: true

# os and/or architecture to use when referencing container images (e.g. "windows/armv6" or "arm64")
# same as --platform; SYFT_PLATFORM env var
platform: ""

# set the list of package catalogers to use when generating the SBOM
# default = empty (cataloger set determined automatically by the source type [image or file/directory])
# catalogers:
#   - alpmdb-cataloger
#   - apkdb-cataloger
#   - binary-cataloger
#   - cargo-auditable-binary-cataloger
#   - cocoapods-cataloger
#   - conan-cataloger
#   - dartlang-lock-cataloger
#   - dotnet-deps-cataloger
#   - dpkgdb-cataloger
#   - elixir-mix-lock-cataloger
#   - erlang-rebar-lock-cataloger
#   - go-mod-file-cataloger
#   - go-module-binary-cataloger
#   - graalvm-native-image-cataloger
#   - haskell-cataloger
#   - java-cataloger
#   - java-gradle-lockfile-cataloger
#   - java-pom-cataloger
#   - javascript-lock-cataloger
#   - javascript-package-cataloger
#   - linux-kernel-cataloger
#   - nix-store-cataloger
#   - php-composer-installed-cataloger
#   - php-composer-lock-cataloger
#   - portage-cataloger
#   - python-index-cataloger
#   - python-package-cataloger
#   - rpm-db-cataloger
#   - rpm-file-cataloger
#   - ruby-gemfile-cataloger
#   - ruby-gemspec-cataloger
#   - rust-cargo-lock-cataloger
#   - sbom-cataloger
#   - spm-cataloger
catalogers:

# cataloging packages is exposed through the packages and power-user subcommands
package:

  # search within archives that do contain a file index to search against (zip)
  # note: for now this only applies to the java package cataloger
  # SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES env var
  search-indexed-archives: true

  # search within archives that do not contain a file index to search against (tar, tar.gz, tar.bz2, etc)
  # note: enabling this may result in a performance impact since all discovered compressed tars will be decompressed
  # note: for now this only applies to the java package cataloger
  # SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES env var
  search-unindexed-archives: false

  cataloger:
    # enable/disable cataloging of packages
    # SYFT_PACKAGE_CATALOGER_ENABLED env var
    enabled: true

    # the search space to look for packages (options: all-layers, squashed)
    # same as -s ; SYFT_PACKAGE_CATALOGER_SCOPE env var
    scope: "squashed"

golang:
   # search for go package licences in the GOPATH of the system running Syft, note that this is outside the
   # container filesystem and potentially outside the root of a local directory scan
   # SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES env var
   search-local-mod-cache-licenses: false
   
   # specify an explicit go mod cache directory, if unset this defaults to $GOPATH/pkg/mod or $HOME/go/pkg/mod
   # SYFT_GOLANG_LOCAL_MOD_CACHE_DIR env var
   local-mod-cache-dir: ""

   # search for go package licences by retrieving the package from a network proxy
   # SYFT_GOLANG_SEARCH_REMOTE_LICENSES env var
   search-remote-licenses: false

   # remote proxy to use when retrieving go packages from the network,
   # if unset this defaults to $GOPROXY followed by https://proxy.golang.org
   # SYFT_GOLANG_PROXY env var
   proxy: ""

   # specifies packages which should not be fetched by proxy
   # if unset this defaults to $GONOPROXY
   # SYFT_GOLANG_NOPROXY env var
   no-proxy: ""

linux-kernel:
   # whether to catalog linux kernel modules found within lib/modules/** directories
   # SYFT_LINUX_KERNEL_CATALOG_MODULES env var
   catalog-modules: true

python:
   # when running across entries in requirements.txt that do not specify a specific version 
   # (e.g. "sqlalchemy >= 1.0.0, <= 2.0.0, != 3.0.0, <= 3.0.0"), attempt to guess what the version could
   # be based on the version requirements specified (e.g. "1.0.0"). When enabled the lowest expressible version 
   # when given an arbitrary constraint will be used (even if that version may not be available/published).
   guess-unpinned-requirements: false

# cataloging file contents is exposed through the power-user subcommand
file-contents:
  cataloger:
    # enable/disable cataloging of secrets
    # SYFT_FILE_CONTENTS_CATALOGER_ENABLED env var
    enabled: true

    # the search space to look for secrets (options: all-layers, squashed)
    # SYFT_FILE_CONTENTS_CATALOGER_SCOPE env var
    scope: "squashed"

  # skip searching a file entirely if it is above the given size (default = 1MB; unit = bytes)
  # SYFT_FILE_CONTENTS_SKIP_FILES_ABOVE_SIZE env var
  skip-files-above-size: 1048576

  # file globs for the cataloger to match on
  # SYFT_FILE_CONTENTS_GLOBS env var
  globs: []

# cataloging file metadata is exposed through the power-user subcommand
file-metadata:
  cataloger:
    # enable/disable cataloging of file metadata
    # SYFT_FILE_METADATA_CATALOGER_ENABLED env var
    enabled: true

    # the search space to look for file metadata (options: all-layers, squashed)
    # SYFT_FILE_METADATA_CATALOGER_SCOPE env var
    scope: "squashed"

  # the file digest algorithms to use when cataloging files (options: "md5", "sha1", "sha224", "sha256", "sha384", "sha512")
  # SYFT_FILE_METADATA_DIGESTS env var
  digests: ["sha256"]

# maximum number of workers used to process the list of package catalogers in parallel
parallelism: 1

# cataloging secrets is exposed through the power-user subcommand
secrets:
  cataloger:
    # enable/disable cataloging of secrets
    # SYFT_SECRETS_CATALOGER_ENABLED env var
    enabled: true

    # the search space to look for secrets (options: all-layers, squashed)
    # SYFT_SECRETS_CATALOGER_SCOPE env var
    scope: "all-layers"

  # show extracted secret values in the final JSON report
  # SYFT_SECRETS_REVEAL_VALUES env var
  reveal-values: false

  # skip searching a file entirely if it is above the given size (default = 1MB; unit = bytes)
  # SYFT_SECRETS_SKIP_FILES_ABOVE_SIZE env var
  skip-files-above-size: 1048576

  # name-regex pairs to consider when searching files for secrets. Note: the regex must match single line patterns
  # but may also have OPTIONAL multiline capture groups. Regexes with a named capture group of "value" will
  # use the entire regex to match, but the secret value will be assumed to be entirely contained within the
  # "value" named capture group.
  additional-patterns: {}

  # names to exclude from the secrets search, valid values are: "aws-access-key", "aws-secret-key", "pem-private-key",
  # "docker-config-auth", and "generic-api-key". Note: this does not consider any names introduced in the
  # "secrets.additional-patterns" config option.
  # SYFT_SECRETS_EXCLUDE_PATTERN_NAMES env var
  exclude-pattern-names: []

# options that apply to all scan sources
source:
  # alias name for the source
  # SYFT_SOURCE_NAME env var; --source-name flag
  name: ""
   
  # alias version for the source
  # SYFT_SOURCE_VERSION env var; --source-version flag
  version: ""
   
  # options affecting the file source type
  file:
    # the file digest algorithms to use on the scanned file (options: "md5", "sha1", "sha224", "sha256", "sha384", "sha512")
    digests: ["sha256"]

# options when pulling directly from a registry via the "registry:" or "containerd:" scheme
registry:
  # skip TLS verification when communicating with the registry
  # SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY env var
  insecure-skip-tls-verify: false

  # use http instead of https when connecting to the registry
  # SYFT_REGISTRY_INSECURE_USE_HTTP env var
  insecure-use-http: false

  # filepath to a CA certificate (or directory containing *.crt, *.cert, *.pem) used to generate the client certificate
  # SYFT_REGISTRY_CA_CERT env var
  ca-cert: ""

  # credentials for specific registries
  auth:
      # the URL to the registry (e.g. "docker.io", "localhost:5000", etc.)
      # SYFT_REGISTRY_AUTH_AUTHORITY env var
    - authority: ""

      # SYFT_REGISTRY_AUTH_USERNAME env var
      username: ""

      # SYFT_REGISTRY_AUTH_PASSWORD env var
      password: ""

      # note: token and username/password are mutually exclusive
      # SYFT_REGISTRY_AUTH_TOKEN env var
      token: ""

      # filepath to the client certificate used for TLS authentication to the registry
      # SYFT_REGISTRY_AUTH_TLS_CERT env var
      tls-cert: ""

      # filepath to the client key used for TLS authentication to the registry
      # SYFT_REGISTRY_AUTH_TLS_KEY env var
      tls-key: ""
    
    # - ... # note, more credentials can be provided via config file only (not env vars)

# generate an attested SBOM
attest:
  # path to the private key file to use for attestation
  # SYFT_ATTEST_KEY env var
  key: "cosign.key"

  # password to decrypt to given private key
  # SYFT_ATTEST_PASSWORD env var, additionally responds to COSIGN_PASSWORD
  password: ""

log:
  # use structured logging
  # same as SYFT_LOG_STRUCTURED env var
  structured: false

  # the log level; note: detailed logging suppress the ETUI
  # same as SYFT_LOG_LEVEL env var
  level: "error"

  # location to write the log file (default is not to have a log file)
  # same as SYFT_LOG_FILE env var
  file: ""
```

### Adding an SBOM to an image as an attestation using Syft

`syft attest --output [FORMAT] --key [KEY] [SOURCE] [flags]`

SBOMs themselves can serve as input to different analysis tools. [Grype](https://github.com/anchore/grype), a vulnerability scanner CLI tool from Anchore, is one such tool. Publishers of container images can use attestations to enable their consumers to trust Syft-generated SBOM descriptions of those container images. To create and provide these attestations, image publishers can run `syft attest` in conjunction with the [cosign](https://github.com/sigstore/cosign) tool to attach SBOM attestations to their images.

#### Example attestation
Note for the following example replace `docker.io/image:latest` with an image you own. You should also have push access to
its remote reference. Replace `$MY_PRIVATE_KEY` with a private key you own or have generated with cosign.

```bash
syft attest --key $MY_PRIVATE_KEY -o spdx-json docker.io/image:latest > image_latest_sbom_attestation.json
cosign attach attestation --attestation image_latest_sbom_attestation.json docker.io/image:latest
```

Verify the new attestation exists on your image.

```bash
cosign verify-attestation --key $MY_PUBLIC_KEY --type spdxjson docker.io/image:latest | jq '.payload | @base64d | .payload | fromjson | .predicate'
```

You should see this output along with the attached SBOM:

```
Verification for docker.io/image:latest --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.
```

Consumers of your image can now trust that the SBOM associated with your image is correct and from a trusted source.

The SBOM can be piped to Grype:


```bash
cosign verify-attestation --key $MY_PUBLIC_KEY --type spdxjson docker.io/image:latest | jq '.payload | @base64d | .payload | fromjson | .predicate' | grype
```
