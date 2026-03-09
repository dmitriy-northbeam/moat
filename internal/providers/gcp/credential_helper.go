package gcp

import "encoding/json"

// CredentialHelperScript is a shell script that fetches GCP access tokens
// from the moat proxy. It outputs the token in a format compatible with
// GCP external account executable-sourced credentials.
//
// This requires curl, which is always installed as a base package in containers
// built with the dependency system (see internal/deps/dockerfile.go). Since
// --grant gcp requires the gcloud dependency for the GCP CLI, curl is guaranteed
// to be present in any container using GCP credentials.
const CredentialHelperScript = `#!/bin/sh
set -e
if [ -z "$AGENTOPS_GCP_CREDENTIAL_URL" ]; then
  echo "AGENTOPS_GCP_CREDENTIAL_URL not set" >&2
  exit 1
fi
if [ -n "$AGENTOPS_CREDENTIAL_TOKEN" ]; then
  exec curl -sf -m 10 -H "Authorization: Bearer $AGENTOPS_CREDENTIAL_TOKEN" "$AGENTOPS_GCP_CREDENTIAL_URL"
else
  exec curl -sf -m 10 "$AGENTOPS_GCP_CREDENTIAL_URL"
fi
`

// GetCredentialHelper returns the credential helper script as bytes.
func GetCredentialHelper() []byte {
	return []byte(CredentialHelperScript)
}

// ExternalCredentialConfig returns a GCP external account JSON config that
// uses an executable-sourced credential. The GCP SDK reads this config and
// invokes the helper script to obtain access tokens.
//
// See: https://google.aip.dev/auth/4117
func ExternalCredentialConfig(helperPath string) ([]byte, error) {
	config := map[string]interface{}{
		"type":               "external_account",
		"audience":           "//iam.googleapis.com/projects/-/serviceAccounts/-",
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_url":          "https://sts.googleapis.com/v1/token",
		"credential_source": map[string]interface{}{
			"executable": map[string]interface{}{
				"command":        helperPath,
				"timeout_millis": 10000,
				"output_type":    "json",
			},
		},
	}

	return json.MarshalIndent(config, "", "  ")
}
