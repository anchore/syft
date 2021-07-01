# syft

[![Validations](https://github.com/anchore/syft/actions/workflows/validations.yaml/badge.svg)](https://github.com/anchore/syft/actions/workflows/validations.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/anchore/syft)](https://goreportcard.com/report/github.com/anchore/syft)
[![GitHub release](https://img.shields.io/github/release/anchore/syft.svg)](https://github.com/anchore/syft/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/syft/blob/main/LICENSE)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/anchore/syft.svg)](https://github.com/anchore/syft)

A CLI tool and go library for generating a Software Bill of Materials (SBOM) from container images and filesystems. Exceptional for vulnerability detection when used with a scanner tool like [Grype](https://github.com/anchore/grype).

## Happening soon: [OSS Virtual Meetup](https://get.anchore.com/anchore-oss-meetup-jun-30-2021/)

[**Register here!**](https://get.anchore.com/anchore-oss-meetup-jun-30-2021/)

**When:** June 30, 11am-noon PT

**What:** 3 fast-paced talks, with time for Q&A

- **Using Syft to Streamline Compliance** (Chet Burgess — Principal Engineer, Cisco)


- **Fast Container Scanning in CI: Three Ways to Use Grype in Your Builds** (Dan Luhring — Manager of Open Source Engineering, Anchore)


- **Building More Optimal Container Images with Dive** (Alex Goodman — Creator of [Dive](https://github.com/wagoodman/dive), Sr Software Engineer for Open Source, Anchore)


![syft-demo](https://user-images.githubusercontent.com/590471/90277200-2a253000-de33-11ea-893f-32c219eea11a.gif)

**Features**
- Catalog container images and filesystems to discover packages and libraries.
- Supports packages and libraries from various ecosystems (APK, DEB, RPM, Ruby Bundles, Python Wheel/Egg/requirements.txt, JavaScript NPM/Yarn, Java JAR/EAR/WAR, Jenkins plugins JPI/HPI, Go modules)
- Linux distribution identification (supports Alpine, BusyBox, CentOS/RedHat, Debian/Ubuntu flavored distributions)
- Supports Docker and OCI image formats
- Direct support for [Grype](https://github.com/anchore/grype), a fast and powerful vulnerability matcher.


If you encounter an issue, please [let us know using the issue tracker](https://github.com/anchore/syft/issues).

## Getting started

To generate an SBOM for a Docker or OCI image:
```
syft <image>
```

**Note**: This is equivalent to specifying the `packages` subcommand:
```
syft packages <image>
```

The above output includes only software that is visible in the container (i.e., the squashed representation of the image).
To include software from all image layers in the SBOM, regardless of its presence in the final image, provide `--scope all-layers`:

```
syft packages <image> --scope all-layers
```

Syft can generate a SBOM from a variety of sources:
```
# catalog a container image archive (from the result of `docker image save ...`, `podman save ...`, or `skopeo copy` commands)
syft packages path/to/image.tar

# catalog a directory
syft packages path/to/dir
```

Sources can be explicitly provided with a scheme:
```
docker:yourrepo/yourimage:tag          use images from the Docker daemon
docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
dir:path/to/yourproject                read directly from a path on disk (any directory)
registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
```

The output format for Syft is configurable as well:
```
syft packages <image> -o <format>
```

Where the `format`s available are:
- `json`: Use this to get as much information out of Syft as possible!
- `text`: A row-oriented, human-and-machine-friendly output.
- `cyclonedx`: A XML report conforming to the [CycloneDX 1.2 specification](https://cyclonedx.org/specification/overview/).
- `spdx`: A tag-value formatted report conforming to the [SPDX 2.2 specification](https://spdx.github.io/spdx-spec/).
- `spdx-json`: A JSON report conforming to the [SPDX 2.2 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.2/schemas/spdx-schema.json).
- `table`: A columnar summary (default).

## Installation

**Recommended (macOS and Linux)**
```bash
# install the latest version to /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# install a specific version into a specific dir
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b <SOME_BIN_PATH> <RELEASE_VERSION>
```

**Homebrew (macOS)**
```bash
brew tap anchore/syft
brew install syft
```

## Configuration

Configuration search paths:

- `.syft.yaml`
- `.syft/config.yaml`
- `~/.syft.yaml`
- `<XDG_CONFIG_HOME>/syft/config.yaml`

Configuration options (example values are the default):

```yaml
# the output format of the SBOM report (options: table, text, json)
# same as -o ; SYFT_OUTPUT env var
output: "table"

# suppress all output (except for the SBOM report)
# same as -q ; SYFT_QUIET env var
quiet: false

# enable/disable checking for application updates on startup
# same as SYFT_CHECK_FOR_APP_UPDATE env var
check-for-app-update: true

# cataloging packages is exposed through the packages and power-user subcommands
package:
  cataloger:
    # enable/disable cataloging of packages
    # SYFT_PACKAGE_CATALOGER_ENABLED env var
    enabled: true

    # the search space to look for packages (options: all-layers, squashed)
    # same as -s ; SYFT_PACKAGE_CATALOGER_SCOPE env var
    scope: "squashed"

# cataloging file classifications is exposed through the power-user subcommand
file-classification:
  cataloger:
    # enable/disable cataloging of file classifications
    # SYFT_FILE_CLASSIFICATION_CATALOGER_ENABLED env var
    enabled: true

    # the search space to look for file classifications (options: all-layers, squashed)
    # SYFT_FILE_CLASSIFICATION_CATALOGER_SCOPE env var
    scope: "squashed"

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

  # the file digest algorithms to use when cataloging files (options: "sha256", "md5", "sha1")
  # SYFT_FILE_METADATA_DIGESTS env var
  digests: ["sha256"]

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

# options when pulling directly from a registry via the "registry:" scheme
registry:
  # skip TLS verification when communicating with the registry
  # SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY env var
  insecure-skip-tls-verify: false

  # credentials for specific registries
  auth:
    - # the URL to the registry (e.g. "docker.io", "localhost:5000", etc.)
      # SYFT_REGISTRY_AUTH_AUTHORITY env var
      authority: ""
      # SYFT_REGISTRY_AUTH_USERNAME env var
      username: ""
      # SYFT_REGISTRY_AUTH_PASSWORD env var
      password: ""
      # note: token and username/password are mutually exclusive
      # SYFT_REGISTRY_AUTH_TOKEN env var
      token: ""
    - ... # note, more credentials can be provided via config file only

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

# uploading package SBOM is exposed through the packages subcommand
anchore:
  # (feature-preview) the Anchore Enterprise Host or URL to upload results to (supported on Enterprise 3.0+)
  # same as -H ; SYFT_ANCHORE_HOST env var
  host: ""

  # (feature-preview) the path after the host to the Anchore External API (supported on Enterprise 3.0+)
  # same as SYFT_ANCHORE_PATH env var
  path: ""

  # (feature-preview) the username to authenticate against Anchore Enterprise (supported on Enterprise 3.0+)
  # same as -u ; SYFT_ANCHORE_USERNAME env var
  username: ""

  # (feature-preview) the password to authenticate against Anchore Enterprise (supported on Enterprise 3.0+)
  # same as -p ; SYFT_ANCHORE_PASSWORD env var
  password: ""

  # (feature-preview) path to dockerfile to be uploaded with the syft results to Anchore Enterprise (supported on Enterprise 3.0+)
  # same as -d ; SYFT_ANCHORE_DOCKERFILE env var
  dockerfile: ""

```
