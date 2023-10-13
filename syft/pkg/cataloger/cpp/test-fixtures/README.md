# Conan test data

This folder contains the test data for the Conan package manager.

## conan.lock

The conan lock file is created in the following way.

We explicitly use a package which has dependencies, which in turn also have dependendencies.
This is necessary to verify that the dependency tree is properly parsed.

1. Use `conan lock create --reference "mfast/1.2.2#c6f6387c9b99780f0ee05e25f99d0f39"`
2. Manually modify the user and channel of mfast package, to be able to test that it is properly set in SBOM:  
   `sed -i 's|mfast/1.2.2#c6f6387c9b99780f0ee05e25f99d0f39|mfast/1.2.2@my_user/my_channel#c6f6387c9b99780f0ee05e25f99d0f39|g' conan.lock`
3. Manually delete the package id and prev from tinyxml2 entry to test conan lock parsing if they are missing:  
   `sed -i 's|\"package_id\": \"6557f18ca99c0b6a233f43db00e30efaa525e27e\",||g' conan.lock`    
   `sed -i 's|\"prev\": \"548bb273d2980991baa519453d68e5cd\",||g' conan.lock`