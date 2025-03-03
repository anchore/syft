# Debian Archive Cataloger Test Fixtures

This directory contains test fixtures used by the Debian archive cataloger tests.

## Adding Test Fixtures

To add a new test fixture:

1. Place a simple Debian package (.deb) file in this directory
2. Name it with a descriptive name (e.g., `simple-package.deb`, `complex-package-with-conffiles.deb`, etc.)
3. Ensure the .deb file is small and doesn't contain sensitive information
4. Update the test file to use the new fixture

## Current Fixtures

- `toilet_0.3-1.4build1_amd64.deb` - A real Debian package for the "toilet" utility, which is a small text-based tool that creates ASCII art banners. This package contains a control file, md5sums file, and other metadata needed to test the Debian archive cataloger.

## About the "toilet" Package

The `toilet` package is a good test fixture because:
1. It's small in size
2. It's a common/standard Debian package 
3. It contains all the necessary metadata files
4. It's publicly available in Debian/Ubuntu repositories

## Generating Test Fixtures

If you need to create additional test fixtures, you can create minimal Debian packages using the following steps:

```bash
# Create directory structure
mkdir -p ./test-pkg/DEBIAN
mkdir -p ./test-pkg/usr/bin

# Create simple control file
cat > ./test-pkg/DEBIAN/control << EOF
Package: test-package
Version: 1.0.0
Section: base
Priority: optional
Architecture: all
Depends: libc6
Maintainer: Syft Test <syft@example.com>
Description: Test package for Syft Debian cataloger
 This is a test package created for testing the Syft
 Debian archive cataloger functionality.
EOF

# Create conffiles entry (optional)
echo "/etc/test-package/config.conf" > ./test-pkg/DEBIAN/conffiles

# Create md5sums file (optional)
echo "d41d8cd98f00b204e9800998ecf8427e  usr/bin/test-command" > ./test-pkg/DEBIAN/md5sums

# Create a dummy executable
echo '#!/bin/sh\necho "Hello from test package"' > ./test-pkg/usr/bin/test-command
chmod +x ./test-pkg/usr/bin/test-command

# Build the package
dpkg-deb --build test-pkg

# Rename output file
mv test-pkg.deb custom-test-package.deb
```