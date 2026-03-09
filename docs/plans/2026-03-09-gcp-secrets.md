# GCP Secrets Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add GCP service account impersonation as a credential provider, mirroring the existing AWS credential endpoint pattern.

**Architecture:** GCP uses the same credential endpoint pattern as AWS. The proxy serves temporary access tokens via `generateAccessToken` (IAM Credentials API), and the container fetches them via a credential helper script. The GCP SDK reads credentials from an external credential config file pointed to by `GOOGLE_APPLICATION_CREDENTIALS`.

**Tech Stack:** `cloud.google.com/go/iam/credentials/apiv1`, `google.golang.org/api/option`, `google.golang.org/protobuf`

---

### Task 1: Add GCP SDK dependency

**Step 1: Add GCP IAM credentials SDK**

Run:
```bash
cd /Users/dmitriy/workspace/moat && go get cloud.google.com/go/iam@latest
```

**Step 2: Verify it resolves**

Run:
```bash
go mod tidy
```

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "feat(provider): add GCP IAM credentials SDK dependency"
```

---

### Task 2: Register GCP as a known credential provider

**Files:**
- Modify: `internal/credential/types.go`

**Step 1: Add ProviderGCP constant and update KnownProviders/IsKnownProvider**

In `internal/credential/types.go`, add `ProviderGCP` to the const block:

```go
ProviderGCP       Provider = "gcp"
```

Add it to the `base` slice in `KnownProviders()` and the switch in `IsKnownProvider()`.

**Step 2: Verify it compiles**

Run:
```bash
go build ./internal/credential/...
```

**Step 3: Commit**

```bash
git add internal/credential/types.go
git commit -m "feat(provider): register GCP as known credential provider"
```

---

### Task 3: Create GCP provider package — provider.go

**Files:**
- Create: `internal/providers/gcp/doc.go`
- Create: `internal/providers/gcp/provider.go`

**Step 1: Write doc.go**

```go
// Package gcp implements the GCP credential provider for moat.
//
// Like the AWS provider, GCP uses a credential endpoint pattern rather than
// header injection. The provider exposes an HTTP endpoint that returns
// temporary access tokens from IAM generateAccessToken.
//
// The container is configured with GOOGLE_APPLICATION_CREDENTIALS pointing
// to an external credential config that fetches tokens from the proxy endpoint.
//
// Grant flow:
//  1. User provides service account email via `moat grant gcp`
//  2. Email is validated and tested with generateAccessToken
//  3. Service account email stored in Credential.Token, project/lifetime in Metadata
//
// Runtime flow:
//  1. Container makes GCP API call
//  2. GCP SDK reads GOOGLE_APPLICATION_CREDENTIALS
//  3. External credential config fetches token from proxy endpoint
//  4. Proxy calls IAM generateAccessToken and returns access token
//  5. SDK uses token for the API call
package gcp
```

**Step 2: Write provider.go**

```go
package gcp

import (
	"context"
	"net/http"

	"github.com/majorcontext/moat/internal/provider"
)

// Provider implements provider.CredentialProvider and provider.EndpointProvider
// for GCP credentials via service account impersonation.
type Provider struct{}

// Compile-time interface assertions.
var (
	_ provider.CredentialProvider = (*Provider)(nil)
	_ provider.EndpointProvider   = (*Provider)(nil)
)

// New creates a new GCP provider.
func New() *Provider {
	return &Provider{}
}

func init() {
	provider.Register(New())
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "gcp"
}

// Grant acquires GCP credentials by prompting for a service account email.
func (p *Provider) Grant(ctx context.Context) (*provider.Credential, error) {
	return grant(ctx)
}

// ConfigureProxy is a no-op for GCP since it uses the endpoint pattern.
func (p *Provider) ConfigureProxy(pc provider.ProxyConfigurer, cred *provider.Credential) {
	// No-op: GCP uses credential endpoint, not proxy header injection
}

// ContainerEnv returns nil; the run manager sets GOOGLE_APPLICATION_CREDENTIALS.
func (p *Provider) ContainerEnv(cred *provider.Credential) []string {
	return nil
}

// ContainerMounts returns nil; GCP doesn't require any mounts.
func (p *Provider) ContainerMounts(cred *provider.Credential, containerHome string) ([]provider.MountConfig, string, error) {
	return nil, "", nil
}

// Cleanup is a no-op for GCP.
func (p *Provider) Cleanup(cleanupPath string) {
	// No cleanup needed
}

// ImpliedDependencies returns dependencies implied by GCP grant.
func (p *Provider) ImpliedDependencies() []string {
	return []string{"gcloud"}
}

// RegisterEndpoints registers the GCP credential endpoint handler.
func (p *Provider) RegisterEndpoints(mux *http.ServeMux, cred *provider.Credential) {
	handler := NewEndpointHandler(cred)
	mux.Handle("/gcp-credentials", handler)
}
```

**Step 3: Verify it compiles**

Run:
```bash
go build ./internal/providers/gcp/...
```
Expected: may fail because `grant` and `NewEndpointHandler` don't exist yet. That's fine, we'll add them in the next tasks.

**Step 4: Commit**

```bash
git add internal/providers/gcp/
git commit -m "feat(provider): add GCP provider skeleton"
```

---

### Task 4: Create GCP provider — grant.go

**Files:**
- Create: `internal/providers/gcp/grant.go`

**Step 1: Write grant.go**

This file handles:
- Context keys for passing CLI flags
- Service account email validation
- Test impersonation via `generateAccessToken`
- Config extraction from stored credentials

```go
package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/majorcontext/moat/internal/provider"
	"github.com/majorcontext/moat/internal/provider/util"
)

// Metadata keys for GCP credentials.
const (
	MetaKeyProject  = "project"
	MetaKeyLifetime = "lifetime"
)

// Default values.
const (
	DefaultLifetime = 1 * time.Hour
)

// Default OAuth scopes for GCP access tokens.
var DefaultScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// Context keys for passing grant options from CLI.
type ctxKey string

const (
	ctxKeyServiceAccount ctxKey = "gcp_service_account"
	ctxKeyProject        ctxKey = "gcp_project"
	ctxKeyLifetime       ctxKey = "gcp_lifetime"
)

// WithGrantOptions returns a context with GCP grant options set.
func WithGrantOptions(ctx context.Context, serviceAccount, project, lifetime string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyServiceAccount, serviceAccount)
	ctx = context.WithValue(ctx, ctxKeyProject, project)
	ctx = context.WithValue(ctx, ctxKeyLifetime, lifetime)
	return ctx
}

// Config holds GCP service account impersonation configuration.
type Config struct {
	ServiceAccount string
	Project        string
	Lifetime       time.Duration
}

// grant acquires GCP credentials by prompting for a service account email.
func grant(ctx context.Context) (*provider.Credential, error) {
	var serviceAccount string
	var err error

	// Check for service account in context (from CLI flags)
	if v, ok := ctx.Value(ctxKeyServiceAccount).(string); ok && v != "" {
		serviceAccount = v
	}

	// Prompt if not provided via context
	if serviceAccount == "" {
		serviceAccount, err = util.PromptForToken("Enter GCP service account email")
		if err != nil {
			return nil, &provider.GrantError{
				Provider: "gcp",
				Cause:    err,
				Hint:     "The service account should be in format: NAME@PROJECT.iam.gserviceaccount.com",
			}
		}
	}

	// Validate service account email
	cfg, err := ParseServiceAccount(serviceAccount)
	if err != nil {
		return nil, &provider.GrantError{
			Provider: "gcp",
			Cause:    err,
			Hint:     "Example: my-agent@my-project.iam.gserviceaccount.com",
		}
	}

	// Apply overrides from context
	if v, ok := ctx.Value(ctxKeyProject).(string); ok && v != "" {
		cfg.Project = v
	}
	if v, ok := ctx.Value(ctxKeyLifetime).(string); ok && v != "" {
		if d, parseErr := time.ParseDuration(v); parseErr == nil {
			cfg.Lifetime = d
		}
	}

	// Test generateAccessToken to verify impersonation works
	if err := testGenerateAccessToken(ctx, cfg); err != nil {
		return nil, &provider.GrantError{
			Provider: "gcp",
			Cause:    err,
			Hint: "Ensure you have the Service Account Token Creator role on this service account\n" +
				"and that your GCP credentials are configured (gcloud auth application-default login).\n" +
				"See: https://majorcontext.com/moat/concepts/credentials#gcp",
		}
	}

	// Build credential with service account email as token and config as metadata
	cred := &provider.Credential{
		Provider:  "gcp",
		Token:     cfg.ServiceAccount,
		CreatedAt: time.Now(),
		Metadata: map[string]string{
			MetaKeyLifetime: cfg.Lifetime.String(),
		},
	}

	if cfg.Project != "" {
		cred.Metadata[MetaKeyProject] = cfg.Project
	}

	return cred, nil
}

// ParseServiceAccount validates a GCP service account email and returns a Config.
// Format: NAME@PROJECT.iam.gserviceaccount.com
func ParseServiceAccount(email string) (*Config, error) {
	if email == "" {
		return nil, fmt.Errorf("service account email is required")
	}

	// Must contain @
	atIdx := strings.Index(email, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid service account email: missing '@'")
	}

	name := email[:atIdx]
	domain := email[atIdx+1:]

	if name == "" {
		return nil, fmt.Errorf("invalid service account email: name is empty")
	}

	if !strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		return nil, fmt.Errorf("invalid service account email: must end with .iam.gserviceaccount.com (got %s)", domain)
	}

	// Extract project from domain (PROJECT.iam.gserviceaccount.com)
	project := strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
	if project == "" {
		return nil, fmt.Errorf("invalid service account email: project ID is empty")
	}

	return &Config{
		ServiceAccount: email,
		Project:        project,
		Lifetime:       DefaultLifetime,
	}, nil
}

// testGenerateAccessToken verifies the service account can be impersonated.
func testGenerateAccessToken(ctx context.Context, cfg *Config) error {
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return fmt.Errorf("creating IAM credentials client: %w", err)
	}
	defer client.Close()

	// Request a short-lived token to test impersonation.
	// Use a 10-minute lifetime for the test (minimum useful duration).
	req := &credentialspb.GenerateAccessTokenRequest{
		Name:     "projects/-/serviceAccounts/" + cfg.ServiceAccount,
		Scope:    DefaultScopes,
		Lifetime: durationpb(10 * time.Minute),
	}

	_, err = client.GenerateAccessToken(ctx, req)
	if err != nil {
		return fmt.Errorf("generating access token: %w", err)
	}

	return nil
}

// durationpb converts a time.Duration to a protobuf Duration.
func durationpb(d time.Duration) *durationpb_type {
	return &durationpb_type{Seconds: int64(d.Seconds())}
}

// We need the protobuf duration type. Import it properly.
// Actually, use google.golang.org/protobuf/types/known/durationpb.

// ConfigFromCredential extracts Config from a stored credential.
func ConfigFromCredential(cred *provider.Credential) (*Config, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}

	cfg := &Config{
		ServiceAccount: cred.Token,
		Lifetime:       DefaultLifetime,
	}

	if cred.Metadata != nil {
		if project := cred.Metadata[MetaKeyProject]; project != "" {
			cfg.Project = project
		}

		if lifetimeStr := cred.Metadata[MetaKeyLifetime]; lifetimeStr != "" {
			d, err := time.ParseDuration(lifetimeStr)
			if err != nil {
				return nil, fmt.Errorf("invalid lifetime %q: %w", lifetimeStr, err)
			}
			cfg.Lifetime = d
		}
	}

	return cfg, nil
}
```

Note: The `durationpb` helper above is a placeholder. The actual implementation should use `google.golang.org/protobuf/types/known/durationpb`. Fix imports during implementation to use:

```go
import durationpb "google.golang.org/protobuf/types/known/durationpb"
```

And call `durationpb.New(10 * time.Minute)` instead of the custom helper.

**Step 2: Verify it compiles**

Run:
```bash
go build ./internal/providers/gcp/...
```

**Step 3: Commit**

```bash
git add internal/providers/gcp/grant.go
git commit -m "feat(provider): add GCP grant flow with service account validation"
```

---

### Task 5: Create GCP provider — endpoint.go

**Files:**
- Create: `internal/providers/gcp/endpoint.go`

**Step 1: Write endpoint.go**

This serves GCP access tokens via HTTP, with caching and auth token verification. Mirrors `internal/providers/aws/endpoint.go`.

```go
package gcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"google.golang.org/protobuf/types/known/durationpb"
	"github.com/majorcontext/moat/internal/log"
	"github.com/majorcontext/moat/internal/provider"
	"github.com/majorcontext/moat/internal/ui"
)

// credentialRefreshBuffer is the time before expiration when credentials should be refreshed.
const credentialRefreshBuffer = 5 * time.Minute

// AccessToken holds a temporary GCP access token.
type AccessToken struct {
	Token      string
	Expiration time.Time
}

// IAMGenerateAccessTokener is the interface for generating access tokens (enables testing).
type IAMGenerateAccessTokener interface {
	GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error)
}

// EndpointHandler serves GCP access tokens via HTTP.
type EndpointHandler struct {
	cfg       *Config
	authToken string

	mu         sync.RWMutex
	cached     *AccessToken
	expiration time.Time

	iamClient IAMGenerateAccessTokener
}

// NewEndpointHandler creates a new GCP credential endpoint handler.
func NewEndpointHandler(cred *provider.Credential) *EndpointHandler {
	cfg, err := ConfigFromCredential(cred)
	if err != nil {
		ui.Warnf("Failed to parse GCP config from credential: %v", err)
		cfg = &Config{
			ServiceAccount: cred.Token,
			Lifetime:       DefaultLifetime,
		}
	}

	return &EndpointHandler{
		cfg: cfg,
	}
}

// SetAuthToken sets the required auth token for the credential endpoint.
func (h *EndpointHandler) SetAuthToken(token string) {
	h.authToken = token
}

// SetIAMClient sets a custom IAM client (for testing).
func (h *EndpointHandler) SetIAMClient(client IAMGenerateAccessTokener) {
	h.iamClient = client
}

// ServeHTTP implements http.Handler, returning an access token as JSON.
func (h *EndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Verify auth token if required
	if h.authToken != "" {
		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + h.authToken
		if auth == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(expectedAuth)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	token, err := h.getAccessToken(r.Context())
	if err != nil {
		log.Error("GCP credential fetch error", "error", err)
		http.Error(w, "failed to get credentials", http.StatusInternalServerError)
		return
	}

	// Return in OAuth2 access token format
	resp := map[string]interface{}{
		"access_token": token.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(token.Expiration).Seconds()),
		"expiry":       token.Expiration.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		ui.Warnf("Failed to encode GCP credentials response: %v", err)
	}
}

// getAccessToken returns a cached token or fetches a new one.
func (h *EndpointHandler) getAccessToken(ctx context.Context) (*AccessToken, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	h.mu.RLock()
	if h.cached != nil && time.Now().Add(credentialRefreshBuffer).Before(h.expiration) {
		token := h.cached
		h.mu.RUnlock()
		return token, nil
	}
	h.mu.RUnlock()

	h.mu.Lock()
	defer h.mu.Unlock()

	// Double-check after acquiring write lock
	if h.cached != nil && time.Now().Add(credentialRefreshBuffer).Before(h.expiration) {
		return h.cached, nil
	}

	// Initialize IAM client if needed
	if h.iamClient == nil {
		client, err := credentials.NewIamCredentialsClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating IAM credentials client: %w", err)
		}
		// Wrap in adapter to match interface
		h.iamClient = &iamClientAdapter{client: client}
	}

	req := &credentialspb.GenerateAccessTokenRequest{
		Name:     "projects/-/serviceAccounts/" + h.cfg.ServiceAccount,
		Scope:    DefaultScopes,
		Lifetime: durationpb.New(h.cfg.Lifetime),
	}

	resp, err := h.iamClient.GenerateAccessToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("generating access token for %s: %w", h.cfg.ServiceAccount, err)
	}

	expireTime := resp.GetExpireTime().AsTime()

	h.cached = &AccessToken{
		Token:      resp.GetAccessToken(),
		Expiration: expireTime,
	}
	h.expiration = expireTime

	return h.cached, nil
}

// ServiceAccount returns the configured service account email.
func (h *EndpointHandler) ServiceAccount() string {
	return h.cfg.ServiceAccount
}

// iamClientAdapter wraps the real IAM credentials client to match IAMGenerateAccessTokener.
type iamClientAdapter struct {
	client *credentials.IamCredentialsClient
}

func (a *iamClientAdapter) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
	return a.client.GenerateAccessToken(ctx, req)
}
```

Note: The `IAMGenerateAccessTokener` interface uses `...interface{}` for opts to simplify the mock interface. The real `gax.CallOption` type would add an extra import. During implementation, check whether the `iamClientAdapter` pattern works or if the interface should use `...gax.CallOption` with the `google.golang.org/api/gax` import. Adjust accordingly.

**Step 2: Verify it compiles**

Run:
```bash
go build ./internal/providers/gcp/...
```

**Step 3: Commit**

```bash
git add internal/providers/gcp/endpoint.go
git commit -m "feat(provider): add GCP endpoint handler with token caching"
```

---

### Task 6: Create GCP provider — credential_helper.go

**Files:**
- Create: `internal/providers/gcp/credential_helper.go`

**Step 1: Write credential_helper.go**

Same curl-based helper as AWS. The GCP SDK external credential config calls this script.

```go
package gcp

// CredentialHelperScript is a shell script that fetches GCP access tokens
// from the Moat proxy. It's called by the GCP SDK external credential config.
//
// This requires curl, which is always installed as a base package in containers.
// The gcloud dependency ensures curl is present.
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

// ExternalCredentialConfig returns a GCP external credential configuration
// that uses the credential helper to fetch tokens. This is written to disk
// and referenced by GOOGLE_APPLICATION_CREDENTIALS.
//
// See: https://cloud.google.com/iam/docs/reference/credentials/rest
// and: https://google.aip.dev/auth/4117 (executable-sourced credentials)
func ExternalCredentialConfig(helperPath string) []byte {
	// The GCP SDK supports "executable-sourced credentials" via
	// GOOGLE_APPLICATION_CREDENTIALS pointing to a JSON config.
	config := `{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/-/serviceAccounts/-",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "executable": {
      "command": "` + helperPath + `",
      "timeout_millis": 15000,
      "output_type": "json"
    }
  }
}
`
	return []byte(config)
}
```

Note: The external credential config format above uses the executable-sourced credentials spec from GCP. During implementation, verify this is the correct format by checking the GCP documentation for `external_account` type with `executable` source. The helper script returns JSON with `access_token` and `expiry` fields.

**Step 2: Verify it compiles**

Run:
```bash
go build ./internal/providers/gcp/...
```

**Step 3: Commit**

```bash
git add internal/providers/gcp/credential_helper.go
git commit -m "feat(provider): add GCP credential helper and external config"
```

---

### Task 7: Write GCP provider tests

**Files:**
- Create: `internal/providers/gcp/provider_test.go`

**Step 1: Write provider_test.go**

Test the provider, service account parsing, config extraction, and endpoint handler:

```go
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/majorcontext/moat/internal/provider"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProvider_Name(t *testing.T) {
	p := New()
	if got := p.Name(); got != "gcp" {
		t.Errorf("Name() = %q, want %q", got, "gcp")
	}
}

func TestProvider_ImpliedDependencies(t *testing.T) {
	p := New()
	deps := p.ImpliedDependencies()
	if len(deps) != 1 || deps[0] != "gcloud" {
		t.Errorf("ImpliedDependencies() = %v, want [gcloud]", deps)
	}
}

func TestProvider_ContainerEnv(t *testing.T) {
	p := New()
	cred := &provider.Credential{Token: "agent@project.iam.gserviceaccount.com"}
	env := p.ContainerEnv(cred)
	if env != nil {
		t.Errorf("ContainerEnv() = %v, want nil", env)
	}
}

func TestProvider_ContainerMounts(t *testing.T) {
	p := New()
	cred := &provider.Credential{Token: "agent@project.iam.gserviceaccount.com"}
	mounts, cleanupPath, err := p.ContainerMounts(cred, "/home/user")
	if err != nil {
		t.Errorf("ContainerMounts() error = %v", err)
	}
	if mounts != nil {
		t.Errorf("ContainerMounts() mounts = %v, want nil", mounts)
	}
	if cleanupPath != "" {
		t.Errorf("ContainerMounts() cleanupPath = %q, want empty", cleanupPath)
	}
}

func TestParseServiceAccount(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		wantSA     string
		wantProj   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:     "valid service account",
			email:    "agent@my-project.iam.gserviceaccount.com",
			wantSA:   "agent@my-project.iam.gserviceaccount.com",
			wantProj: "my-project",
		},
		{
			name:     "valid with hyphens and numbers",
			email:    "my-agent-123@project-456.iam.gserviceaccount.com",
			wantSA:   "my-agent-123@project-456.iam.gserviceaccount.com",
			wantProj: "project-456",
		},
		{
			name:    "empty email",
			email:   "",
			wantErr: true,
			errMsg:  "service account email is required",
		},
		{
			name:    "missing @",
			email:   "agentmy-project.iam.gserviceaccount.com",
			wantErr: true,
			errMsg:  "missing '@'",
		},
		{
			name:    "empty name",
			email:   "@my-project.iam.gserviceaccount.com",
			wantErr: true,
			errMsg:  "name is empty",
		},
		{
			name:    "wrong domain",
			email:   "agent@my-project.example.com",
			wantErr: true,
			errMsg:  "must end with .iam.gserviceaccount.com",
		},
		{
			name:    "missing project",
			email:   "agent@.iam.gserviceaccount.com",
			wantErr: true,
			errMsg:  "project ID is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseServiceAccount(tt.email)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseServiceAccount(%q) = nil error, want error containing %q", tt.email, tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseServiceAccount(%q) error = %q, want error containing %q", tt.email, err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseServiceAccount(%q) unexpected error: %v", tt.email, err)
				return
			}
			if cfg.ServiceAccount != tt.wantSA {
				t.Errorf("ServiceAccount = %q, want %q", cfg.ServiceAccount, tt.wantSA)
			}
			if cfg.Project != tt.wantProj {
				t.Errorf("Project = %q, want %q", cfg.Project, tt.wantProj)
			}
			if cfg.Lifetime != DefaultLifetime {
				t.Errorf("Lifetime = %v, want %v", cfg.Lifetime, DefaultLifetime)
			}
		})
	}
}

func TestConfigFromCredential(t *testing.T) {
	t.Run("basic credential", func(t *testing.T) {
		cred := &provider.Credential{
			Token: "agent@project.iam.gserviceaccount.com",
		}
		cfg, err := ConfigFromCredential(cred)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ServiceAccount != cred.Token {
			t.Errorf("ServiceAccount = %q, want %q", cfg.ServiceAccount, cred.Token)
		}
		if cfg.Lifetime != DefaultLifetime {
			t.Errorf("Lifetime = %v, want %v", cfg.Lifetime, DefaultLifetime)
		}
	})

	t.Run("with metadata", func(t *testing.T) {
		cred := &provider.Credential{
			Token: "agent@project.iam.gserviceaccount.com",
			Metadata: map[string]string{
				MetaKeyProject:  "my-project",
				MetaKeyLifetime: "2h",
			},
		}
		cfg, err := ConfigFromCredential(cred)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Project != "my-project" {
			t.Errorf("Project = %q, want %q", cfg.Project, "my-project")
		}
		if cfg.Lifetime != 2*time.Hour {
			t.Errorf("Lifetime = %v, want %v", cfg.Lifetime, 2*time.Hour)
		}
	})

	t.Run("nil credential", func(t *testing.T) {
		_, err := ConfigFromCredential(nil)
		if err == nil {
			t.Error("expected error for nil credential")
		}
	})

	t.Run("invalid lifetime", func(t *testing.T) {
		cred := &provider.Credential{
			Token: "agent@project.iam.gserviceaccount.com",
			Metadata: map[string]string{
				MetaKeyLifetime: "invalid",
			},
		}
		_, err := ConfigFromCredential(cred)
		if err == nil {
			t.Error("expected error for invalid lifetime")
		}
	})
}

func TestEndpointHandler_ServeHTTP(t *testing.T) {
	t.Run("returns access token", func(t *testing.T) {
		expiration := time.Now().Add(1 * time.Hour)
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "agent@project.iam.gserviceaccount.com",
				Lifetime:       1 * time.Hour,
			},
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
					return &credentialspb.GenerateAccessTokenResponse{
						AccessToken: "ya29.test-access-token",
						ExpireTime:  timestamppb.New(expiration),
					}, nil
				},
			},
		}

		req := httptest.NewRequest("GET", "/gcp-credentials", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["access_token"] != "ya29.test-access-token" {
			t.Errorf("access_token = %v, want ya29.test-access-token", resp["access_token"])
		}
		if resp["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", resp["token_type"])
		}
		if _, ok := resp["expiry"]; !ok {
			t.Error("expiry missing from response")
		}
	})

	t.Run("returns 500 on provider error", func(t *testing.T) {
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "agent@project.iam.gserviceaccount.com",
				Lifetime:       1 * time.Hour,
			},
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
					return nil, fmt.Errorf("IAM error")
				},
			},
		}

		req := httptest.NewRequest("GET", "/gcp-credentials", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", w.Code)
		}
	})

	t.Run("returns 401 when auth token required but missing", func(t *testing.T) {
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "agent@project.iam.gserviceaccount.com",
				Lifetime:       1 * time.Hour,
			},
			authToken: "secret-token",
		}

		req := httptest.NewRequest("GET", "/gcp-credentials", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("returns 401 when auth token is invalid", func(t *testing.T) {
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "agent@project.iam.gserviceaccount.com",
				Lifetime:       1 * time.Hour,
			},
			authToken: "secret-token",
		}

		req := httptest.NewRequest("GET", "/gcp-credentials", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("returns token when auth is valid", func(t *testing.T) {
		expiration := time.Now().Add(1 * time.Hour)
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "agent@project.iam.gserviceaccount.com",
				Lifetime:       1 * time.Hour,
			},
			authToken: "secret-token",
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
					return &credentialspb.GenerateAccessTokenResponse{
						AccessToken: "ya29.test-access-token",
						ExpireTime:  timestamppb.New(expiration),
					}, nil
				},
			},
		}

		req := httptest.NewRequest("GET", "/gcp-credentials", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp["access_token"] != "ya29.test-access-token" {
			t.Errorf("access_token = %v, want ya29.test-access-token", resp["access_token"])
		}
	})
}

func TestEndpointHandler_Caching(t *testing.T) {
	callCount := 0
	expiration := time.Now().Add(1 * time.Hour)

	handler := &EndpointHandler{
		cfg: &Config{
			ServiceAccount: "agent@project.iam.gserviceaccount.com",
			Lifetime:       1 * time.Hour,
		},
		iamClient: &mockIAMClient{
			generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
				callCount++
				return &credentialspb.GenerateAccessTokenResponse{
					AccessToken: fmt.Sprintf("ya29.token-%d", callCount),
					ExpireTime:  timestamppb.New(expiration),
				}, nil
			},
		},
	}

	// First call should hit IAM
	token1, err := handler.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	// Second call should use cache
	token2, err := handler.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1 (cached)", callCount)
	}

	if token1.Token != token2.Token {
		t.Errorf("cached tokens should match")
	}
}

func TestEndpointHandler_RefreshesExpiredToken(t *testing.T) {
	callCount := 0

	handler := &EndpointHandler{
		cfg: &Config{
			ServiceAccount: "agent@project.iam.gserviceaccount.com",
			Lifetime:       1 * time.Hour,
		},
		iamClient: &mockIAMClient{
			generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
				callCount++
				// Return token expiring within 5-min buffer
				expiration := time.Now().Add(3 * time.Minute)
				return &credentialspb.GenerateAccessTokenResponse{
					AccessToken: fmt.Sprintf("ya29.token-%d", callCount),
					ExpireTime:  timestamppb.New(expiration),
				}, nil
			},
		},
	}

	// First call
	_, err := handler.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	// Second call should refresh
	_, err = handler.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("callCount = %d, want 2 (should refresh near-expiry token)", callCount)
	}
}

// mockIAMClient implements IAMGenerateAccessTokener for testing.
type mockIAMClient struct {
	generateAccessTokenFn func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error)
}

func (m *mockIAMClient) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
	return m.generateAccessTokenFn(ctx, req, opts...)
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

**Step 2: Run the tests**

Run:
```bash
go test ./internal/providers/gcp/... -v
```

**Step 3: Commit**

```bash
git add internal/providers/gcp/provider_test.go
git commit -m "test(provider): add GCP provider unit tests"
```

---

### Task 8: Create proxy GCP credential provider

**Files:**
- Create: `internal/proxy/gcp.go`
- Create: `internal/proxy/gcp_test.go`

**Step 1: Write gcp.go**

Mirrors `internal/proxy/aws.go`. Used by the daemon to serve GCP credentials.

```go
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"google.golang.org/protobuf/types/known/durationpb"
	"github.com/majorcontext/moat/internal/log"
	"github.com/majorcontext/moat/internal/ui"
)

// GCPAccessToken holds a temporary GCP access token.
type GCPAccessToken struct {
	Token      string
	Expiration time.Time
}

// GCPCredentialHandler serves GCP access tokens via HTTP.
type GCPCredentialHandler struct {
	getCredentials func(ctx context.Context) (*GCPAccessToken, error)
	authToken      string
}

// ServeHTTP implements http.Handler, returning access token as JSON.
func (h *GCPCredentialHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.authToken != "" {
		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + h.authToken
		if auth == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(expectedAuth)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	token, err := h.getCredentials(r.Context())
	if err != nil {
		log.Error("GCP credential fetch error", "error", err)
		http.Error(w, "failed to get credentials", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"access_token": token.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(token.Expiration).Seconds()),
		"expiry":       token.Expiration.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		ui.Warnf("Failed to encode GCP credentials response: %v", err)
	}
}

// IAMGenerateAccessTokener interface for IAM operations (enables testing).
type IAMGenerateAccessTokener interface {
	GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error)
}

// GCPCredentialProvider manages GCP credential fetching and caching.
type GCPCredentialProvider struct {
	serviceAccount string
	project        string
	lifetime       time.Duration
	authToken      string

	mu         sync.RWMutex
	cached     *GCPAccessToken
	expiration time.Time

	iamClient IAMGenerateAccessTokener
}

// NewGCPCredentialProvider creates a new GCP credential provider.
func NewGCPCredentialProvider(ctx context.Context, serviceAccount, project string, lifetime time.Duration) (*GCPCredentialProvider, error) {
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating IAM credentials client: %w", err)
	}

	return &GCPCredentialProvider{
		serviceAccount: serviceAccount,
		project:        project,
		lifetime:       lifetime,
		iamClient:      &proxyIAMClientAdapter{client: client},
	}, nil
}

// SetAuthToken sets the required auth token for the credential endpoint.
func (p *GCPCredentialProvider) SetAuthToken(token string) {
	p.authToken = token
}

// Handler returns an HTTP handler for serving credentials.
func (p *GCPCredentialProvider) Handler() http.Handler {
	return &GCPCredentialHandler{
		getCredentials: p.GetCredentials,
		authToken:      p.authToken,
	}
}

// ServiceAccount returns the configured service account email.
func (p *GCPCredentialProvider) ServiceAccount() string {
	return p.serviceAccount
}

// Project returns the configured GCP project.
func (p *GCPCredentialProvider) Project() string {
	return p.project
}

// GetCredentials returns cached credentials or fetches new ones.
func (p *GCPCredentialProvider) GetCredentials(ctx context.Context) (*GCPAccessToken, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	p.mu.RLock()
	if p.cached != nil && time.Now().Add(credentialRefreshBuffer).Before(p.expiration) {
		token := p.cached
		p.mu.RUnlock()
		return token, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cached != nil && time.Now().Add(credentialRefreshBuffer).Before(p.expiration) {
		return p.cached, nil
	}

	req := &credentialspb.GenerateAccessTokenRequest{
		Name:     "projects/-/serviceAccounts/" + p.serviceAccount,
		Scope:    []string{"https://www.googleapis.com/auth/cloud-platform"},
		Lifetime: durationpb.New(p.lifetime),
	}

	resp, err := p.iamClient.GenerateAccessToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("generating access token for %s: %w", p.serviceAccount, err)
	}

	expireTime := resp.GetExpireTime().AsTime()

	p.cached = &GCPAccessToken{
		Token:      resp.GetAccessToken(),
		Expiration: expireTime,
	}
	p.expiration = expireTime

	return p.cached, nil
}

// proxyIAMClientAdapter wraps the real IAM credentials client.
type proxyIAMClientAdapter struct {
	client *credentials.IamCredentialsClient
}

func (a *proxyIAMClientAdapter) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
	return a.client.GenerateAccessToken(ctx, req)
}
```

**Step 2: Write gcp_test.go**

```go
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGCPCredentialHandler_ServeHTTP(t *testing.T) {
	t.Run("returns access token", func(t *testing.T) {
		expiration := time.Now().Add(1 * time.Hour)
		handler := &GCPCredentialHandler{
			getCredentials: func(ctx context.Context) (*GCPAccessToken, error) {
				return &GCPAccessToken{
					Token:      "ya29.test-access-token",
					Expiration: expiration,
				}, nil
			},
		}

		req := httptest.NewRequest("GET", "/_gcp/credentials", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["access_token"] != "ya29.test-access-token" {
			t.Errorf("access_token = %v, want ya29.test-access-token", resp["access_token"])
		}
		if resp["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", resp["token_type"])
		}
	})

	t.Run("returns 500 on provider error", func(t *testing.T) {
		handler := &GCPCredentialHandler{
			getCredentials: func(ctx context.Context) (*GCPAccessToken, error) {
				return nil, context.DeadlineExceeded
			},
		}

		req := httptest.NewRequest("GET", "/_gcp/credentials", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", w.Code)
		}
	})

	t.Run("returns 401 when auth token required but missing", func(t *testing.T) {
		handler := &GCPCredentialHandler{
			getCredentials: func(ctx context.Context) (*GCPAccessToken, error) {
				return &GCPAccessToken{Token: "ya29.test", Expiration: time.Now().Add(time.Hour)}, nil
			},
			authToken: "secret-token",
		}

		req := httptest.NewRequest("GET", "/_gcp/credentials", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("returns 401 when auth token is invalid", func(t *testing.T) {
		handler := &GCPCredentialHandler{
			getCredentials: func(ctx context.Context) (*GCPAccessToken, error) {
				return &GCPAccessToken{Token: "ya29.test", Expiration: time.Now().Add(time.Hour)}, nil
			},
			authToken: "secret-token",
		}

		req := httptest.NewRequest("GET", "/_gcp/credentials", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("returns token when auth is valid", func(t *testing.T) {
		handler := &GCPCredentialHandler{
			getCredentials: func(ctx context.Context) (*GCPAccessToken, error) {
				return &GCPAccessToken{Token: "ya29.test", Expiration: time.Now().Add(time.Hour)}, nil
			},
			authToken: "secret-token",
		}

		req := httptest.NewRequest("GET", "/_gcp/credentials", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})
}

func TestGCPCredentialProvider_Caching(t *testing.T) {
	callCount := 0
	expiration := time.Now().Add(1 * time.Hour)

	mockIAM := &mockProxyIAMClient{
		generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
			callCount++
			return &credentialspb.GenerateAccessTokenResponse{
				AccessToken: fmt.Sprintf("ya29.token-%d", callCount),
				ExpireTime:  timestamppb.New(expiration),
			}, nil
		},
	}

	prov := &GCPCredentialProvider{
		serviceAccount: "agent@project.iam.gserviceaccount.com",
		lifetime:       1 * time.Hour,
		iamClient:      mockIAM,
	}

	// First call should hit IAM
	token1, err := prov.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	// Second call should use cache
	token2, err := prov.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1 (cached)", callCount)
	}

	if token1.Token != token2.Token {
		t.Errorf("cached tokens should match")
	}
}

func TestGCPCredentialProvider_RefreshesExpiredCredentials(t *testing.T) {
	callCount := 0

	mockIAM := &mockProxyIAMClient{
		generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
			callCount++
			expiration := time.Now().Add(3 * time.Minute) // within 5-min buffer
			return &credentialspb.GenerateAccessTokenResponse{
				AccessToken: fmt.Sprintf("ya29.token-%d", callCount),
				ExpireTime:  timestamppb.New(expiration),
			}, nil
		},
	}

	prov := &GCPCredentialProvider{
		serviceAccount: "agent@project.iam.gserviceaccount.com",
		lifetime:       1 * time.Hour,
		iamClient:      mockIAM,
	}

	_, err := prov.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	_, err = prov.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("callCount = %d, want 2 (should refresh near-expiry token)", callCount)
	}
}

type mockProxyIAMClient struct {
	generateAccessTokenFn func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error)
}

func (m *mockProxyIAMClient) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...interface{}) (*credentialspb.GenerateAccessTokenResponse, error) {
	return m.generateAccessTokenFn(ctx, req, opts...)
}
```

**Step 3: Run tests**

Run:
```bash
go test ./internal/proxy/ -run TestGCP -v
```

**Step 4: Commit**

```bash
git add internal/proxy/gcp.go internal/proxy/gcp_test.go
git commit -m "feat(proxy): add GCP credential provider with caching"
```

---

### Task 9: Register GCP provider in providers package

**Files:**
- Modify: `internal/providers/register.go`

**Step 1: Add GCP import**

Add to the import block:
```go
_ "github.com/majorcontext/moat/internal/providers/gcp" // registers GCP provider
```

**Step 2: Verify it compiles**

Run:
```bash
go build ./internal/providers/...
```

**Step 3: Commit**

```bash
git add internal/providers/register.go
git commit -m "feat(provider): register GCP provider on import"
```

---

### Task 10: Add GCP to daemon — runcontext, api, server, persist

**Files:**
- Modify: `internal/daemon/runcontext.go`
- Modify: `internal/daemon/api.go`
- Modify: `internal/daemon/server.go`
- Modify: `internal/daemon/persist.go`

**Step 1: Add GCPConfig to api.go**

In `internal/daemon/api.go`, add after the `AWSConfig` type:

```go
// GCPConfig holds GCP credential provider configuration.
type GCPConfig struct {
	ServiceAccount string        `json:"service_account"`
	Project        string        `json:"project,omitempty"`
	Lifetime       time.Duration `json:"lifetime"`
}
```

Add to `RegisterRequest`:
```go
GCPConfig *GCPConfig `json:"gcp_config,omitempty"`
```

Add `import "time"` if not already present.

**Step 2: Add GCP fields to runcontext.go**

In `RunContext` struct, add after `AWSConfig`:
```go
GCPConfig *GCPConfig `json:"gcp_config,omitempty"`
```

Add after `awsHandler`:
```go
gcpHandler http.Handler `json:"-"` // GCP credential endpoint handler
```

Add `SetGCPHandler` method:
```go
// SetGCPHandler stores the GCP credential endpoint handler for this run.
func (rc *RunContext) SetGCPHandler(h http.Handler) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.gcpHandler = h
}
```

In `ToRunContext()` (api.go), add after `rc.AWSConfig = req.AWSConfig`:
```go
rc.GCPConfig = req.GCPConfig
```

In `ToProxyContextData()`, add after `d.AWSHandler = rc.awsHandler`:
```go
d.GCPHandler = rc.gcpHandler
```

**Step 3: Add GCP setup in server.go**

In `handleRegisterRun`, after the AWS credential provider block, add:
```go
// Create GCP credential provider if configured.
if req.GCPConfig != nil {
	gcpProvider, gcpErr := proxy.NewGCPCredentialProvider(
		runCtx,
		req.GCPConfig.ServiceAccount,
		req.GCPConfig.Project,
		req.GCPConfig.Lifetime,
	)
	if gcpErr != nil {
		log.Warn("failed to create GCP credential provider for run",
			"run_id", rc.RunID, "error", gcpErr)
	} else {
		gcpProvider.SetAuthToken(token)
		rc.SetGCPHandler(gcpProvider.Handler())
	}
}
```

**Step 4: Add GCP restoration in persist.go**

After the AWS provider restoration block, add:
```go
if pr.GCPConfig != nil {
	gcpProvider, gcpErr := proxy.NewGCPCredentialProvider(
		runCtx,
		pr.GCPConfig.ServiceAccount,
		pr.GCPConfig.Project,
		pr.GCPConfig.Lifetime,
	)
	if gcpErr != nil {
		log.Warn("restore: failed to create GCP credential provider",
			"run_id", pr.RunID, "error", gcpErr)
	} else {
		gcpProvider.SetAuthToken(pr.AuthToken)
		rc.SetGCPHandler(gcpProvider.Handler())
	}
}
```

**Step 5: Verify it compiles**

Run:
```bash
go build ./internal/daemon/...
```

**Step 6: Commit**

```bash
git add internal/daemon/api.go internal/daemon/runcontext.go internal/daemon/server.go internal/daemon/persist.go
git commit -m "feat(daemon): add GCP credential provider support"
```

---

### Task 11: Add GCP to proxy routing

**Files:**
- Modify: `internal/proxy/proxy.go`

**Step 1: Add gcpHandler field to Proxy struct**

After `awsHandler`:
```go
gcpHandler http.Handler // Optional handler for GCP credential endpoint
```

**Step 2: Add GCPHandler to RunContextData**

After `AWSHandler`:
```go
GCPHandler http.Handler
```

**Step 3: Add SetGCPHandler method**

After `SetAWSHandler`:
```go
// SetGCPHandler sets the handler for GCP credential requests.
func (p *Proxy) SetGCPHandler(h http.Handler) {
	p.gcpHandler = h
}
```

**Step 4: Add getGCPHandlerForRequest**

After `getAWSHandlerForRequest`:
```go
// getGCPHandlerForRequest returns the GCP handler from RunContextData
// or falls back to the proxy's own handler.
func (p *Proxy) getGCPHandlerForRequest(r *http.Request) http.Handler {
	if rc := getRunContext(r); rc != nil && rc.GCPHandler != nil {
		return rc.GCPHandler
	}
	return p.gcpHandler
}
```

**Step 5: Add handleDirectGCPCredentials**

After `handleDirectAWSCredentials`:
```go
func (p *Proxy) handleDirectGCPCredentials(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}
	token := auth[7:]

	rc, found := p.contextResolver(token)
	if !found {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if rc.GCPHandler == nil {
		http.Error(w, "GCP credentials not configured for this run", http.StatusNotFound)
		return
	}

	ctx := context.WithValue(r.Context(), runContextKey, rc)
	r = r.WithContext(ctx)
	rc.GCPHandler.ServeHTTP(w, r)
}
```

**Step 6: Add routing in ServeHTTP**

In `ServeHTTP`, after the `/_aws/` direct request block, add:
```go
// Direct GCP credential endpoint requests from containers.
if p.contextResolver != nil && r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/_gcp/") {
	p.handleDirectGCPCredentials(w, r)
	return
}
```

After the proxied AWS handler block (`if awsH := p.getAWSHandlerForRequest(r)...`), add:
```go
// Handle GCP credential endpoint
if gcpH := p.getGCPHandlerForRequest(r); gcpH != nil && strings.HasPrefix(r.URL.Path, "/_gcp/credentials") {
	gcpH.ServeHTTP(w, r)
	return
}
```

**Step 7: Verify it compiles**

Run:
```bash
go build ./internal/proxy/...
```

**Step 8: Commit**

```bash
git add internal/proxy/proxy.go
git commit -m "feat(proxy): add GCP credential endpoint routing"
```

---

### Task 12: Add GCP to run manager

**Files:**
- Modify: `internal/run/run.go`
- Modify: `internal/run/manager.go`

**Step 1: Add GCP fields to Run struct**

In `internal/run/run.go`, after `awsTempDir`:
```go
// GCP credential provider (set when using gcp grant)
GCPCredentialProvider *proxy.GCPCredentialProvider

// gcpTempDir is the temp directory for GCP credential helper (cleaned up on destroy)
gcpTempDir string
```

**Step 2: Add GCP credential setup in manager.go**

In the grant processing loop (where `provider.GetEndpoint` is called), add a GCP case. After the AWS endpoint provider block:

```go
// Handle GCP endpoint provider
if providerName == "gcp" {
	if ep := provider.GetEndpoint("gcp"); ep != nil {
		gcpCfg, err := gcpprov.ConfigFromCredential(provCred)
		if err != nil {
			return nil, fmt.Errorf("parsing GCP credential: %w", err)
		}

		gcpProvider, err := proxy.NewGCPCredentialProvider(
			ctx,
			gcpCfg.ServiceAccount,
			gcpCfg.Project,
			gcpCfg.Lifetime,
		)
		if err != nil {
			return nil, fmt.Errorf("creating GCP credential provider: %w", err)
		}
		r.GCPCredentialProvider = gcpProvider

		runCtx.GCPConfig = &daemon.GCPConfig{
			ServiceAccount: gcpCfg.ServiceAccount,
			Project:        gcpCfg.Project,
			Lifetime:       gcpCfg.Lifetime,
		}
	}
}
```

Add the import:
```go
gcpprov "github.com/majorcontext/moat/internal/providers/gcp"
```

**Step 3: Add GCP credential_process setup**

After the AWS credential_process setup block, add:

```go
// Set up GCP credential config if GCP grant is active
if r.GCPCredentialProvider != nil {
	gcpDir, err := os.MkdirTemp("", "agentops-gcp-*")
	if err != nil {
		cleanupDaemonRun()
		return nil, fmt.Errorf("creating GCP credential helper directory: %w", err)
	}
	r.gcpTempDir = gcpDir

	// Write the credential helper script
	helperPath := filepath.Join(gcpDir, "credential-helper")
	if err := os.WriteFile(helperPath, gcpprov.GetCredentialHelper(), 0700); err != nil {
		cleanupDaemonRun()
		return nil, fmt.Errorf("writing GCP credential helper: %w", err)
	}

	// Write external credential config for GCP SDK
	credConfigPath := filepath.Join(gcpDir, "credentials.json")
	credConfig := gcpprov.ExternalCredentialConfig("/agentops/gcp/credential-helper")
	if err := os.WriteFile(credConfigPath, credConfig, 0644); err != nil {
		cleanupDaemonRun()
		return nil, fmt.Errorf("writing GCP credential config: %w", err)
	}

	// Mount the directory
	mounts = append(mounts, container.MountConfig{
		Source:   gcpDir,
		Target:   "/agentops/gcp",
		ReadOnly: true,
	})

	// Build credential endpoint URL
	credentialURL := "http://" + proxyHost + "/_gcp/credentials"

	// Set environment variables
	proxyEnv = append(proxyEnv,
		"GOOGLE_APPLICATION_CREDENTIALS=/agentops/gcp/credentials.json",
		"AGENTOPS_GCP_CREDENTIAL_URL="+credentialURL,
		// GCP traffic goes through proxy for firewall/observability.
		// Tell gcloud/SDK to trust our CA for MITM SSL.
		"REQUESTS_CA_BUNDLE="+caCertInContainer,
		"CURL_CA_BUNDLE="+caCertInContainer,
	)

	if r.GCPCredentialProvider.Project() != "" {
		proxyEnv = append(proxyEnv,
			"CLOUDSDK_CORE_PROJECT="+r.GCPCredentialProvider.Project(),
			"GCLOUD_PROJECT="+r.GCPCredentialProvider.Project(),
		)
	}

	// Include auth token if proxy requires it
	if regResp != nil && regResp.AuthToken != "" {
		proxyEnv = append(proxyEnv, "AGENTOPS_CREDENTIAL_TOKEN="+regResp.AuthToken)
	}

	fmt.Printf("GCP credential config configured (service account: %s)\n",
		r.GCPCredentialProvider.ServiceAccount())
}
```

**Step 4: Add GCP temp dir to cleanup**

In the cleanup section, add `r.gcpTempDir` to the temp directory cleanup loop:
```go
for _, dir := range []string{r.awsTempDir, r.gcpTempDir, r.ClaudeConfigTempDir, r.CodexConfigTempDir, r.GeminiConfigTempDir} {
```

**Step 5: Verify it compiles**

Run:
```bash
go build ./internal/run/...
```

**Step 6: Commit**

```bash
git add internal/run/run.go internal/run/manager.go
git commit -m "feat(run): add GCP credential setup to run manager"
```

---

### Task 13: Add GCP CLI grant command

**Files:**
- Modify: `cmd/moat/cli/grant.go`
- Modify: `cmd/moat/cli/grant_providers.go`

**Step 1: Add GCP flags and handling to grant.go**

Add GCP flag variables:
```go
var (
	gcpServiceAccount string
	gcpProject        string
	gcpLifetime       string
)
```

Add flags in `init()`:
```go
grantCmd.Flags().StringVar(&gcpServiceAccount, "service-account", "", "GCP service account email (required for gcp)")
grantCmd.Flags().StringVar(&gcpProject, "project", "", "GCP project ID")
grantCmd.Flags().StringVar(&gcpLifetime, "lifetime", "", "Access token lifetime (default: 1h, max: 12h)")
```

Add import:
```go
"github.com/majorcontext/moat/internal/providers/gcp"
```

In `runGrant`, after the AWS `--role` validation block, add:
```go
// For GCP, validate required flags before calling Grant
if providerName == "gcp" && gcpServiceAccount == "" {
	return fmt.Errorf(`--service-account is required for GCP grant

Usage: moat grant gcp --service-account=NAME@PROJECT.iam.gserviceaccount.com

Options:
  --service-account  GCP service account email (required)
  --project          GCP project ID (default: extracted from email)
  --lifetime         Access token lifetime (default: 1h, max: 12h)`)
}
```

After the AWS context setup, add:
```go
// For GCP, pass the CLI flags via context
if providerName == "gcp" {
	ctx = gcp.WithGrantOptions(ctx, gcpServiceAccount, gcpProject, gcpLifetime)
}
```

**Step 2: Add GCP to grant_providers.go**

In `goProviderDescriptions`, add:
```go
"gcp": "GCP service account impersonation",
```

**Step 3: Verify it compiles**

Run:
```bash
go build ./cmd/moat/...
```

**Step 4: Commit**

```bash
git add cmd/moat/cli/grant.go cmd/moat/cli/grant_providers.go
git commit -m "feat(cli): add moat grant gcp command"
```

---

### Task 14: Run all tests and lint

**Step 1: Run unit tests**

Run:
```bash
make test-unit
```

**Step 2: Run lint**

Run:
```bash
make lint
```

If `golangci-lint` is not installed, fall back to:
```bash
go vet ./...
```

**Step 3: Fix any issues**

Fix lint/vet/test errors as needed.

**Step 4: Commit fixes if any**

```bash
git add -u
git commit -m "fix(provider): address lint and test issues for GCP provider"
```

---

### Task 15: Update documentation

**Files:**
- Modify: `docs/content/reference/01-cli.md` — add `moat grant gcp` section
- Modify: `docs/content/reference/02-moat-yaml.md` — add `gcp` to grants list

**Step 1: Add GCP grant documentation to CLI reference**

Add a section near the existing AWS grant docs:

```markdown
### `moat grant gcp`

Grant GCP access via service account impersonation.

```bash
moat grant gcp --service-account=NAME@PROJECT.iam.gserviceaccount.com
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--service-account` | Service account email (required) | — |
| `--project` | GCP project ID | Extracted from email |
| `--lifetime` | Token lifetime | 1h |

**Prerequisites:**
- GCP credentials configured (`gcloud auth application-default login`)
- Service Account Token Creator role on the target service account
```

**Step 2: Add `gcp` to moat.yaml grants list**

In the grants documentation, add `gcp` as a supported provider.

**Step 3: Commit**

```bash
git add docs/
git commit -m "docs(provider): add GCP grant documentation"
```
