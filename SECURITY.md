# Security Policy

## Supported Versions

Security updates are applied only to the most recent release, try to always be up to date.

## Reporting a Vulnerability

To report a security issue, please email
[security@anchore.com](mailto:security@anchore.com)
with a description of the issue, the steps you took to create the issue,
affected versions, and, if known, mitigations for the issue.

All support will be made on a best effort basis, so please indicate the "urgency level" of the vulnerability as Critical, High, Medium or Low.

For more details, see our [security policy documentation](https://oss.anchore.com/docs/contributing/security/).

## Trust Boundary

Syft is a tool to scan content and product an SBOM. Syft is not a tool designed to scan malicious content. Detecting and properly reporting on purposely malicious artifacts is outside the scope of Syft's expected operating environment.

There are many possible ways for malicious content to cause Syft to become confused or fail to include results in an SBOM. We do not consider this to be a security vulnerability.

**Examples**
- Removing or altering a package lock file
- Removing or altering an RPM or DEB database
- A malicious archive that Syft will skip but the runtime may not
- Self modifying systems that change state when running

We consider the security trust boundary for Syft to be anything that causes problems for the overall system running Syft, or Syft operating in a way that is dangerous to itself, the system, or the operator.

**Examples**
- Filling up temp space permanently
- Syft executing arbitrary code when scanning an artifact
- Syft leaking secrets from the environment or configuration files into logs or SBOMs
- Syft operating outside of the expected artifact or directory (directory traversal)
