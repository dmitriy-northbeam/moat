// Package gcp implements the GCP credential provider for moat.
//
// Like the AWS provider, GCP uses a credential endpoint pattern rather than
// proxy header injection. The provider exposes an HTTP endpoint that returns
// temporary OAuth 2.0 access tokens generated via IAM generateAccessToken.
//
// The container is configured with a GCP external credential config that
// points to a credential helper script. The script fetches tokens from the
// proxy's credential endpoint, allowing GCP client libraries to automatically
// obtain credentials when needed.
//
// Grant flow:
//  1. User provides service account email via `moat grant gcp`
//  2. Email is validated and tested with IAM generateAccessToken
//  3. Service account stored in Credential.Token, project/lifetime in Metadata
//
// Runtime flow:
//  1. Container makes GCP API call
//  2. GCP SDK reads GOOGLE_APPLICATION_CREDENTIALS pointing to external config
//  3. External config executes credential helper script
//  4. Script fetches token from proxy endpoint
//  5. Proxy calls IAM generateAccessToken and returns access token
//  6. SDK uses token for the API call
package gcp
