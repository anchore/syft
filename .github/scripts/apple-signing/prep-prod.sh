#!/usr/bin/env bash
set -eu

assert_in_ci

function setup_signing() {
  # Write signing certificate to disk from environment variable.
  CERT_FILE="$HOME/developer_id_certificate.p12"
  echo -n "$APPLE_DEVELOPER_ID_CERT" | base64 --decode > "$CERT_FILE"

  # In order to have all keychain interactions avoid an interactive user prompt, we need to control the password for the keychain in question, which means we need to create a new keychain into which we'll import the signing certificate and from which we'll later access this certificate during code signing.
  EPHEMERAL_KEYCHAIN="ci-ephemeral-keychain"
  EPHEMERAL_KEYCHAIN_PASSWORD="$(openssl rand -base64 100)"
  security create-keychain -p "${EPHEMERAL_KEYCHAIN_PASSWORD}" "${EPHEMERAL_KEYCHAIN}"

  # Import signing certificate into the keychain. (This is a pre-requisite for gon, which is invoked via goreleaser.)
  EPHEMERAL_KEYCHAIN_FULL_PATH="$HOME/Library/Keychains/${EPHEMERAL_KEYCHAIN}-db"
  security import "${CERT_FILE}" -k "${EPHEMERAL_KEYCHAIN_FULL_PATH}" -P "${APPLE_DEVELOPER_ID_CERT_PASS}" -T "$(command -v codesign)"

  # Setting the partition list for this certificate's private key to include "apple-tool:" and "apple:" allows the codesign command to access this keychain item without an interactive user prompt. (codesign is invoked by gon.)
  security set-key-partition-list -S "apple-tool:,apple:" -s -k "${EPHEMERAL_KEYCHAIN_PASSWORD}" "${EPHEMERAL_KEYCHAIN_FULL_PATH}"

  # Make this new keychain the user's default keychain, so that codesign will be able to find this certificate when we specify it during signing.
  security default-keychain -d "user" -s "${EPHEMERAL_KEYCHAIN_FULL_PATH}"

  # TODO: extract this from the certificate material itself
  export MAC_SIGNING_IDENTITY="Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)"
  echo "MAC_SIGNING_IDENTITY=${IDENTITY}"
}