package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"google.golang.org/protobuf/types/known/durationpb"

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

// DefaultScopes are the default OAuth 2.0 scopes for GCP access tokens.
var DefaultScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// Context keys for passing grant options from CLI.
type ctxKey string

const (
	ctxKeyServiceAccount ctxKey = "gcp_service_account"
	ctxKeyProject        ctxKey = "gcp_project"
	ctxKeyLifetime       ctxKey = "gcp_lifetime"
)

// WithGrantOptions returns a context with GCP grant options set.
// These options are used by Grant() instead of prompting interactively.
func WithGrantOptions(ctx context.Context, serviceAccount, project, lifetime string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyServiceAccount, serviceAccount)
	ctx = context.WithValue(ctx, ctxKeyProject, project)
	ctx = context.WithValue(ctx, ctxKeyLifetime, lifetime)
	return ctx
}

// Config holds GCP service account configuration.
type Config struct {
	ServiceAccount string
	Project        string
	Lifetime       time.Duration
}

// ParseServiceAccount validates a GCP service account email and returns a Config.
// Email format: NAME@PROJECT.iam.gserviceaccount.com
func ParseServiceAccount(email string) (*Config, error) {
	if email == "" {
		return nil, fmt.Errorf("service account email is required")
	}

	atIdx := strings.Index(email, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid service account email: missing '@'")
	}

	name := email[:atIdx]
	if name == "" {
		return nil, fmt.Errorf("invalid service account email: empty name before '@'")
	}

	domain := email[atIdx+1:]
	if !strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		return nil, fmt.Errorf("invalid service account email: must end with .iam.gserviceaccount.com")
	}

	project := strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
	if project == "" {
		return nil, fmt.Errorf("invalid service account email: missing project ID")
	}

	return &Config{
		ServiceAccount: email,
		Project:        project,
		Lifetime:       DefaultLifetime,
	}, nil
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

	// Parse and validate service account email
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

	// Test generateAccessToken to verify the service account is accessible
	if err := testGenerateAccessToken(ctx, cfg); err != nil {
		return nil, &provider.GrantError{
			Provider: "gcp",
			Cause:    err,
			Hint: "Ensure you have the iam.serviceAccountTokenCreator role on this service account\n" +
				"and that your GCP credentials are configured (gcloud auth application-default login).\n" +
				"See: https://majorcontext.com/moat/concepts/credentials#gcp",
		}
	}

	// Build credential with service account as token and config as metadata
	cred := &provider.Credential{
		Provider:  "gcp",
		Token:     cfg.ServiceAccount,
		CreatedAt: time.Now(),
		Metadata: map[string]string{
			MetaKeyProject:  cfg.Project,
			MetaKeyLifetime: cfg.Lifetime.String(),
		},
	}

	return cred, nil
}

// testGenerateAccessToken verifies the service account can be impersonated.
func testGenerateAccessToken(ctx context.Context, cfg *Config) error {
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return fmt.Errorf("creating IAM credentials client: %w", err)
	}
	defer client.Close()

	_, err = client.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name:     fmt.Sprintf("projects/-/serviceAccounts/%s", cfg.ServiceAccount),
		Scope:    DefaultScopes,
		Lifetime: durationpb.New(cfg.Lifetime),
	})
	if err != nil {
		return fmt.Errorf("generating access token: %w", err)
	}

	return nil
}

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
