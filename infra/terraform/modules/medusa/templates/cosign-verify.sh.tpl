#!/usr/bin/env bash
set -euo pipefail

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign binary is required for signature verification" >&2
  exit 1
fi

cosign_key_file="$(mktemp)"
trap 'rm -f "${cosign_key_file}"' EXIT

printf '%s' "${COSIGN_PUBLIC_KEY_BASE64}" | base64 --decode > "${cosign_key_file}"

verify_args=(--key "${cosign_key_file}")
if [[ -n "${COSIGN_CERT_IDENTITY:-}" ]]; then
  verify_args+=(--certificate-identity "${COSIGN_CERT_IDENTITY}")
fi
if [[ -n "${COSIGN_CERT_OIDC_ISSUER:-}" ]]; then
  verify_args+=(--certificate-oidc-issuer "${COSIGN_CERT_OIDC_ISSUER}")
fi

cosign verify --yes "${verify_args[@]}" "${COSIGN_IMAGE}"

if [[ -n "${COSIGN_ATTESTATION_TYPES:-}" ]]; then
  IFS=',' read -r -a attest_types <<< "${COSIGN_ATTESTATION_TYPES}"
  for type in "${attest_types[@]}"; do
    trimmed="$(printf '%s' "${type}" | xargs)"
    if [[ -z "${trimmed}" ]]; then
      continue
    fi
    att_args=("${verify_args[@]}")
    att_args+=(--type "${trimmed}")
    cosign verify-attestation --yes "${att_args[@]}" "${COSIGN_IMAGE}"
  done
fi
