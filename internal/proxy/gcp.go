package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/majorcontext/moat/internal/log"
	"github.com/majorcontext/moat/internal/ui"
	"google.golang.org/protobuf/types/known/durationpb"
)

// defaultGCPScopes are the default OAuth2 scopes requested for GCP access tokens.
var defaultGCPScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// GCPAccessToken holds a GCP OAuth2 access token.
type GCPAccessToken struct {
	Token      string
	Expiration time.Time
}

// GCPCredentialHandler serves GCP access tokens via HTTP.
type GCPCredentialHandler struct {
	getCredentials func(ctx context.Context) (*GCPAccessToken, error)
	authToken      string // Required auth token
}

// ServeHTTP implements http.Handler, returning a GCP access token as JSON.
func (h *GCPCredentialHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Verify auth token if required
	if h.authToken != "" {
		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + h.authToken
		// Use constant-time comparison to prevent timing attacks
		if auth == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(expectedAuth)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	creds, err := h.getCredentials(r.Context())
	if err != nil {
		// Log detailed error server-side but return generic message to prevent leaking sensitive info
		log.Error("GCP credential fetch error", "error", err)
		http.Error(w, "failed to get credentials", http.StatusInternalServerError)
		return
	}

	expiresIn := int64(math.Max(0, time.Until(creds.Expiration).Seconds()))

	resp := map[string]interface{}{
		"access_token": creds.Token,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"expiry":       creds.Expiration.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Response already started, can't send HTTP error. Log and continue.
		ui.Warnf("Failed to encode GCP credentials response: %v", err)
	}
}

// IAMGenerateAccessTokener is an interface for the IAM GenerateAccessToken operation (enables testing).
type IAMGenerateAccessTokener interface {
	GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error)
}

// GCPCredentialProvider manages GCP credential fetching and caching.
type GCPCredentialProvider struct {
	serviceAccount string
	project        string
	lifetime       time.Duration
	authToken      string // Auth token for credential endpoint

	mu         sync.RWMutex
	cached     *GCPAccessToken
	expiration time.Time

	// iamClient for making GenerateAccessToken calls (injectable for testing)
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

// ServiceAccount returns the configured GCP service account.
func (p *GCPCredentialProvider) ServiceAccount() string {
	return p.serviceAccount
}

// Project returns the configured GCP project.
func (p *GCPCredentialProvider) Project() string {
	return p.project
}

// GetCredentials returns cached credentials or fetches new ones.
func (p *GCPCredentialProvider) GetCredentials(ctx context.Context) (*GCPAccessToken, error) {
	// Check context before proceeding
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	p.mu.RLock()
	// Return cached if valid with buffer before expiration
	if p.cached != nil && time.Now().Add(credentialRefreshBuffer).Before(p.expiration) {
		creds := p.cached
		p.mu.RUnlock()
		return creds, nil
	}
	p.mu.RUnlock()

	// Need to refresh
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.cached != nil && time.Now().Add(credentialRefreshBuffer).Before(p.expiration) {
		return p.cached, nil
	}

	// Call IAM GenerateAccessToken
	req := &credentialspb.GenerateAccessTokenRequest{
		Name:     fmt.Sprintf("projects/-/serviceAccounts/%s", p.serviceAccount),
		Scope:    defaultGCPScopes,
		Lifetime: durationpb.New(p.lifetime),
	}

	result, err := p.iamClient.GenerateAccessToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("generating access token for %s: %w", p.serviceAccount, err)
	}

	expireTime := result.GetExpireTime().AsTime()

	p.cached = &GCPAccessToken{
		Token:      result.GetAccessToken(),
		Expiration: expireTime,
	}
	p.expiration = expireTime

	return p.cached, nil
}

// proxyIAMClientAdapter wraps a real credentials.IamCredentialsClient to match the IAMGenerateAccessTokener interface.
type proxyIAMClientAdapter struct {
	client *credentials.IamCredentialsClient
}

func (a *proxyIAMClientAdapter) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
	return a.client.GenerateAccessToken(ctx, req, opts...)
}
