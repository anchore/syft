# syft

[![Static Analysis + Unit + Integration](https://github.com/anchore/syft/workflows/Static%20Analysis%20+%20Unit%20+%20Integration/badge.svg)](https://github.com/anchore/syft/actions?query=workflow%3A%22Static+Analysis+%2B+Unit+%2B+Integration%22)
[![Acceptance](https://github.com/anchore/syft/workflows/Acceptance/badge.svg)](https://github.com/anchore/syft/actions?query=workflow%3AAcceptance)
[![Go Report Card](https://goreportcard.com/badge/github.com/anchore/syft)](https://goreportcard.com/report/github.com/anchore/syft)
[![GitHub release](https://img.shields.io/github/release/anchore/syft.svg)](https://github.com/anchore/syft/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/syft/blob/main/LICENSE)

A CLI tool and go library for generating a Software Bill of Materials (SBOM) from container images and filesystems.

![syft-demo](https://user-images.githubusercontent.com/590471/90277200-2a253000-de33-11ea-893f-32c219eea11a.gif)

**Features**
- Catalog container images and filesystems to discover packages and libraries.
- Supports packages and libraries from various ecosystems (APK, DEB, RPM, Ruby Bundles, Python Wheel/Egg/requirements.txt, JavaScript NPM/Yarn, Java JAR/EAR/WAR, Jenkins plugins JPI/HPI, Go modules)
- Linux distribution identification (supports Alpine, BusyBox, CentOS/RedHat, Debian/Ubuntu flavored distributions)
- Supports Docker and OCI image formats

If you encounter an issue, please [let us know using the issue tracker](https://github.com/anchore/syft/issues).

## Getting started

To generate an SBOM for a Docker or OCI image:
```
syft <image>
```

The above output includes only software that is visible in the container (i.e., the squashed representation of the image).
To include software from all image layers in the SBOM, regardless of its presence in the final image, provide `--scope all-layers`:

```
syft <image> --scope all-layers
```

Syft can generate a SBOM from a variety of sources:
```
# catalog a container image archive (from the result of `docker image save ...`, `podman save ...`, or `skopeo copy` commands)
syft path/to/image.tar

# catalog a directory
syft path/to/dir
```

The output format for Syft is configurable as well:
```
syft <image> -o <format>
```

Where the `format`s available are:
- `json`: Use this to get as much information out of Syft as possible!
- `text`: A row-oriented, human-and-machine-friendly output.
- `cyclonedx`: A XML report conforming to the [CycloneDX 1.2](https://cyclonedx.org/) specification.
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

# the search space to look for packages (options: all-layers, squashed)
# same as -s ; SYFT_SCOPE env var
scope: "squashed"

# suppress all output (except for the SBOM report)
# same as -q ; SYFT_QUIET env var
quiet: false

# enable/disable checking for application updates on startup
# same as SYFT_CHECK_FOR_APP_UPDATE env var
check-for-app-update: true

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

anchore:
  # (feature-preview) enable uploading of results to Anchore Enterprise automatically (supported on Enterprise 3.0+)
  # same as SYFT_ANCHORE_UPLOAD_ENABLED env var
  upload-enabled: false

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