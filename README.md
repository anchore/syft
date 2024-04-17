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
- Wordpress plugins

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

```bash
syft <image>
```

The above output includes only software that is visible in the container (i.e., the squashed representation of the image). To include software from all image layers in the SBOM, regardless of its presence in the final image, provide `--scope all-layers`:

```bash
syft <image> --scope all-layers
```

### Supported sources

Syft can generate an SBOM from a variety of sources including images, files, directories, and archives. Syft will attempt to
determine the type of source based on provided input, for example:

```bash
# catalog a container image archive (from the result of `docker image save ...`, `podman save ...`, or `skopeo copy` commands)
syft path/to/image.tar

# catalog a Singularity Image Format (SIF) container
syft path/to/image.sif

# catalog a directory
syft path/to/dir
```

To explicitly specify the source behavior, use the `--from` flag. Allowable options are:

```
docker             use images from the Docker daemon
podman             use images from the Podman daemon
containerd         use images from the Containerd daemon
docker-archive     use a tarball from disk for archives created from "docker save"
oci-archive        use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir            read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
singularity        read directly from a Singularity Image Format (SIF) container on disk
dir                read directly from a path on disk (any directory)
file               read directly from a path on disk (any single file)
registry           pull image directly from a registry (no container runtime required)
```
If a source is not provided and Syft identifies the input as a potential image reference, Syft will attempt to resolve it using:
the Docker, Podman, and Containerd daemons followed by direct registry access, in that order.

This default behavior can be overridden with the `default-image-pull-source` configuration option (See [Configuration](#configuration) for more details).


### File selection

By default, Syft will catalog file details and digests for files that are owned by discovered packages. You can change this behavior by using the `SYFT_FILE_METADATA_SELECTION` environment variable or the `file.metadata.selection` configuration option. The options are:

- `all`: capture all files from the search space
- `owned-by-package`: capture only files owned by packages (default)
- `none`: disable capturing any file information


### Package cataloger selection

#### Concepts

> [!IMPORTANT]  
> Syft uses a different set of catalogers by default when scanning files directly than it does when scanning images

The catalogers for an image scan assumes that package installation steps have already been completed. For example, Syft will identify Python packages that have egg or wheel metadata files under a `site-packages` directory, since this is how the canonical tooling `pip` installs python packages.

The catalogers for a directory scan will look for installed software as well as declared dependencies that are not necessarily installed. For example, dependencies listed in a Python `requirements.txt`.

This default set of catalogers being dynamic is critical as this allows Syft to be used in a variety of contexts while still generating accurate SBOMs.
Overriding the set of default catalogers is not recommended for most purposes, however, is possible if needed.

Catalogers can be referenced in two different ways:
- *by name*: the exact cataloger name (e.g. `java-pom-cataloger` or `java-archive-cataloger`)
- *by tag*: a tag that is associated with a cataloger (e.g. `java`)

Syft can take lists of references on the CLI or in the application configuration to define which catalogers to use.

You can **set** the list of catalogers explicitly to use with the `--override-default-catalogers` CLI flag, accepting a comma-separated list of cataloger names or tags.

You can also **add** to, **remove** from, or **sub-select** catalogers to use within the default set of catalogers by using the `--select-catalogers` CLI flag.
  - To **sub-select** catalogers simply provide a tag (e.g. `--select-catalogers TAG`). Catalogers will always be selected from the default set of catalogers (e.g. `--select-catalogers java,go` will select all the `java` catalogers in the default set and all the `go` catalogers in the default set).
  - To **add** a cataloger prefix the cataloger name with `+` (e.g. `--select-catalogers +NAME`). Added catalogers will _always be added_ regardless of removals, filtering, or other defaults.
  - To **remove** a cataloger prefix the cataloger name or tag with `-` (e.g. `--select-catalogers -NAME_OR_TAG`). Catalogers are removed from the set of default catalogers after processing any sub-selections.

These rules and the dynamic default cataloger sets approximates to the following logic:

```
image_catalogers = all_catalogers AND catalogers_tagged("image")

directory_catalogers = all_catalogers AND catalogers_tagged("directory")

default_catalogers = image_catalogers OR directory_catalogers

sub_selected_catalogers = default_catalogers INTERSECT catalogers_tagged(TAG) [ UNION sub_selected_catalogers ... ]

base_catalogers = default_catalogers OR sub_selected_catalogers

final_set = (base_catalogers SUBTRACT removed_catalogers) UNION added_catalogers
```


#### Examples

Only scan for python related packages with catalogers appropriate for the source type (image or directory):
```bash
syft <some container image> --select-catalogers "python"
# results in the following catalogers being used:
# - python-installed-package-cataloger
```

Same command, but the set of catalogers changes based on what is being analyzed (in this case a directory):
```bash
syft <a directory> --select-catalogers "python"
# results in the following catalogers being used:
# - python-installed-package-cataloger
# - python-package-cataloger
```

Use the default set of catalogers and add a cataloger to the set:
```bash
syft ... --select-catalogers "+sbom-cataloger"
```

Use the default set of catalogers but remove any catalogers that deal with RPMs:
```bash
syft ... --select-catalogers "-rpm"
```

Only scan with catalogers that:
- are tagged with "go"
- always use the sbom-cataloger
- are appropriate for the source type (image or directory)

```bash
syft <some container image> --select-catalogers "go,+sbom-cataloger"
# results in the following catalogers being used:
# - go-module-binary-cataloger
# - sbom-cataloger
```

Scan with all catalogers that deal with binary analysis, regardless of the source type:
```bash
syft ... --override-default-catalogers "binary"
# results in the following catalogers being used:
# - binary-cataloger
# - cargo-auditable-binary-cataloger
# - dotnet-portable-executable-cataloger
# - go-module-binary-cataloger
```

Only scan with the specific `go-module-binary-cataloger` and `go-module-file-cataloger` catalogers:
```bash
syft ... --override-default-catalogers "go-module-binary-cataloger,go-module-file-cataloger"
```


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
- `syft-json`: Use this to get as much information out of Syft as possible!
- `syft-text`: A row-oriented, human-and-machine-friendly output.
- `cyclonedx-xml`: A XML report conforming to the [CycloneDX 1.4 specification](https://cyclonedx.org/specification/overview/).
- `cyclonedx-json`: A JSON report conforming to the [CycloneDX 1.4 specification](https://cyclonedx.org/specification/overview/).
- `spdx-tag-value`: A tag-value formatted report conforming to the [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/).
- `spdx-tag-value@2.2`: A tag-value formatted report conforming to the [SPDX 2.2 specification](https://spdx.github.io/spdx-spec/v2.2.2/).
- `spdx-json`: A JSON report conforming to the [SPDX 2.3 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json).
- `spdx-json@2.2`: A JSON report conforming to the [SPDX 2.2 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.2/schemas/spdx-schema.json).
- `github-json`: A JSON report conforming to GitHub's dependency snapshot format.
- `syft-table`: A columnar summary (default).
- `template`: Lets the user specify the output format. See ["Using templates"](#using-templates) below.

## Using templates

Syft lets you define custom output formats, using [Go templates](https://pkg.go.dev/text/template) relative to the Syft JSON output. Here's how it works:

- Define your format as a Go template, and save this template as a file.

- Set the output format to "template" (`-o template`).

- Specify the path to the template file (`-t ./path/to/custom.template`).

- Syft's template processing uses the same data models as the `syft-json` output format — so if you're wondering what data is available as you author a template, you can use the output from `syft <image> -o syft-json` as a reference.

**Example:** You could make Syft output data in CSV format by writing a Go template that renders CSV data and then running `syft <image> -o template -t ~/path/to/csv.tmpl`.

Here's what the `csv.tmpl` file might look like:
```gotemplate
"Package","Version Installed", "Found by"
{{- range .artifacts}}
"{{.name}}","{{.version}}","{{.foundBy}}"
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

> [!NOTE]
> If you have templates being used before Syft v0.102.0 that are no longer working. This is because templating keys were relative to the internal go structs before this version whereas now the keys are relative to the Syft JSON output. To get the legacy behavior back you can set the `format.template.legacy` option to `true` in your configuration.

## Multiple outputs

Syft can also output _multiple_ files in differing formats by appending
`=<file>` to the option, for example to output Syft JSON and SPDX JSON:

```shell
syft <image> -o syft-json=sbom.syft.json -o spdx-json=sbom.spdx.json
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
# the output format(s) of the SBOM report (options: syft-table, syft-text, syft-json, spdx-json, ...)
# to specify multiple output files in differing formats, use a list:
# output:
#   - "syft-json=<syft-json-output-file>"
#   - "spdx-json=<spdx-json-output-file>"
# SYFT_OUTPUT env var / -o, --output flags
output: 
  - "syft-table"

# suppress all output (except for the SBOM report)
# SYFT_QUIET env var / -q flag
quiet: false

# enable/disable checking for application updates on startup
# SYFT_CHECK_FOR_APP_UPDATE env var 
check-for-app-update: true

# maximum number of workers used to process the list of package catalogers in parallel
parallelism: 1

# a list of globs to exclude from scanning, for example:
# exclude:
#   - "/etc/**"
#   - "./out/**/*.json"
# SYFT_EXCLUDE env var / --exclude flag
exclude: []

# os and/or architecture to use when referencing container images (e.g. "windows/armv6" or "arm64")
# SYFT_PLATFORM env var / --platform flag
platform: ""

# the search space to look for file and package data (options: all-layers, squashed)
# SYFT_SCOPE env var
scope: "squashed"

# set the list of package catalogers to use when generating the SBOM
# default = empty (cataloger set determined automatically by the source type [image or file/directory])
# Use `syft cataloger list` for a list of catalogers you can specify
# DEPRECATED: please use default-catalogers and select-catalogers configuration options instead
# SYFT_CATALOGERS env var / --catalogers flag
catalogers:

# set the base set of catalogers to use (defaults to 'image' or 'directory' depending on the scan source)
# SYFT_DEFAULT_CATALOGERS env var / --override-default-catalogers flag
default-catalogers: []

# add, remove, and filter the catalogers to be used
# SYFT_SELECT_CATALOGERS env var / --select-catalogers flag;
select-catalogers: []

# all format configuration
format:
 
  # default value for all formats that support the "pretty" option (default is unset)
  # SYFT_FORMAT_PRETTY env var
  pretty: 

  # all syft-json format options
  json:

    # include space indention and newlines (inherits default value from 'format.pretty' or 'false' if parent is unset)
    # note: inherits default value from 'format.pretty' or 'false' if parent is unset
    # SYFT_FORMAT_JSON_PRETTY env var
    pretty: false
    
    # transform any syft-json output to conform to an approximation of the v11.0.1 schema. This includes:
    # - using the package metadata type names from before v12 of the JSON schema (changed in https://github.com/anchore/syft/pull/1983)
    #
    # Note: this will still include package types and fields that were added at or after json schema v12. This means
    # that output might not strictly be json schema v11 compliant, however, for consumers that require time to port
    # over to the final syft 1.0 json output this option can be used to ease the transition.
    #
    # Note: long term support for this option is not guaranteed (it may change or break at any time).
    # SYFT_FORMAT_JSON_LEGACY env var
    legacy: false

  # all template format options
  template:
    # path to the template file to use when rendering the output with the `template` output format. 
    # Note that all template paths are based on the current syft-json schema.
    # SYFT_FORMAT_TEMPLATE_PATH env var / -t flag 
    path: ""
    
    # if true, uses the go structs for the syft-json format for templating. 
    # if false, uses the syft-json output for templating (which follows the syft JSON schema exactly).
    #
    # Note: long term support for this option is not guaranteed (it may change or break at any time).
    # SYFT_FORMAT_TEMPLATE_LEGACY env var
    legacy: false

  # all spdx-json format options
  spdx-json:

    # include space indention and newlines
    # note: inherits default value from 'format.pretty' or 'false' if parent is unset
    # SYFT_FORMAT_SPDX_JSON_PRETTY env var
    pretty: false

  # all cyclonedx-json format options
  cyclonedx-json:

     # include space indention and newlines
     # note: inherits default value from 'format.pretty' or 'false' if parent is unset
     # SYFT_FORMAT_CYCLONEDX_JSON_PRETTY env var
     pretty: false

  # all cyclonedx-xml format options
  cyclonedx-xml:

     # include space indention
     # note: inherits default value from 'format.pretty' or 'false' if parent is unset
     # SYFT_FORMAT_CYCLONEDX_XML_PRETTY env var
     pretty: false


file:

   metadata: 
      # select which files should be captured by the file-metadata cataloger and included in the SBOM. 
      # Options include:
      #  - "all": capture all files from the search space
      #  - "owned-by-package": capture only files owned by packages
      #  - "none", "": do not capture any files
      # SYFT_FILE_METADATA_SELECTION env var
      selection: "owned-by-package"

      # the file digest algorithms to use when cataloging files (options: "md5", "sha1", "sha224", "sha256", "sha384", "sha512")
      # SYFT_FILE_METADATA_DIGESTS env var
      digests:
      - "sha256"
      - "sha1"

   # capture the contents of select files in the SBOM
   content:
      # skip searching a file entirely if it is above the given size (default = 1MB; unit = bytes)
      # SYFT_FILE_CONTENT_SKIP_FILES_ABOVE_SIZE env var
      skip-files-above-size: 1048576
   
      # file globs for the cataloger to match on
      # SYFT_FILE_CONTENT_GLOBS env var
      globs: []


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

  # allows users to exclude synthetic binary packages from the sbom
  # these packages are removed if an overlap with a non-synthetic package is found
  # SYFT_PACKAGE_EXCLUDE_BINARY_OVERLAP_BY_OWNERSHIP env var
  exclude-binary-overlap-by-ownership: true


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
  
   # the go main module version discovered from binaries built with the go compiler will
   # always show (devel) as the version. Use these options to control heuristics to guess
   # a more accurate version from the binary.
   main-module-version:
      
      # look for LD flags that appear to be setting a version (e.g. -X main.version=1.0.0)
      # SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_LD_FLAGS env var
      from-ld-flags: true
      
      # use the build settings (e.g. vcs.version & vcs.time) to craft a v0 pseudo version 
      # (e.g. v0.0.0-20220308212642-53e6d0aaf6fb) when a more accurate version cannot be found otherwise.
      # SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_BUILD_SETTINGS env var
      from-build-settings: true
      
      # search for semver-like strings in the binary contents.
      # SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_CONTENTS env var
      from-contents: true
  
java:
   maven-url: "https://repo1.maven.org/maven2"
   max-parent-recursive-depth: 5
   # enables Syft to use the network to fill in more detailed information about artifacts
   # currently this enables searching maven-url for license data
   # when running across pom.xml files that could have more information, syft will
   # explicitly search maven for license information by querying the online pom when this is true
   # this option is helpful for when the parent pom has more data,
   # that is not accessible from within the final built artifact
   use-network: false

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

javascript:
  search-remote-licenses: false
  npm-base-url: "https://registry.npmjs.org"


# configuration for the source that the SBOM is generated from (e.g. a file, directory, or container image)
source:
  # alias name for the source
  # SYFT_SOURCE_NAME env var / --source-name flag
  name: ""
   
  # alias version for the source
  # SYFT_SOURCE_VERSION env var / --source-version flag
  version: ""

  # base directory for scanning, no links will be followed above this directory, and all paths will be 
  # reported relative to this directory
  # SYFT_SOURCE_BASE_PATH env var
  base-path: ''

   # options affecting the file source type
  file:
    # the file digest algorithms to use on the scanned file (options: "md5", "sha1", "sha224", "sha256", "sha384", "sha512")
    digests: 
     - "sha256"

  image:
     
    # allows users to specify which image source should be used to generate the sbom
    # valid values are: registry, docker, podman
    # SYFT_SOURCE_IMAGE_DEFAULT_PULL_SOURCE env var
    default-pull-source: ""


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
  # SYFT_LOG_STRUCTURED env var
  structured: false

  # the log level; note: detailed logging suppress the ETUI
  # SYFT_LOG_LEVEL env var
  level: "error"

  # location to write the log file (default is not to have a log file)
  # SYFT_LOG_FILE env var
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
