#!/bin/bash

ESSENTIAL_PACKAGES=(
    "basesystem"
    "filesystem"
    "bash"
)

ESSENTIALS_PATTERN=$(IFS='|'; echo "${ESSENTIAL_PACKAGES[*]}")
ALL_PACKAGES=$(rpm -qa --queryformat '%{NAME}\n')
PACKAGES_TO_REMOVE=()

for package in $ALL_PACKAGES; do
    if ! [[ "$package" =~ ^($ESSENTIALS_PATTERN)$ ]]; then
        PACKAGES_TO_REMOVE+=("$package")
    else
        echo "Skipping essential package: $package"
    fi
done

if [ ${#PACKAGES_TO_REMOVE[@]} -gt 0 ]; then
    echo "Removing non-essential packages..."
    rpm -e --nodeps "${PACKAGES_TO_REMOVE[@]}"
else
    echo "No non-essential packages to remove."
fi

# since we are still in the same terminal and the shell is loaded we can still echo :)
echo "Cleanup complete."