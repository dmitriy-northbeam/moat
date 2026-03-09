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
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/majorcontext/moat/internal/log"
	"github.com/majorcontext/moat/internal/provider"
	"github.com/majorcontext/moat/internal/ui"
)

// credentialRefreshBuffer is the time before expiration when credentials should be refreshed.
const credentialRefreshBuffer = 5 * time.Minute

// AccessToken holds a temporary GCP OAuth 2.0 access token.
type AccessToken struct {
	Token      string
	Expiration time.Time
}

// IAMGenerateAccessTokener is the interface for generating access tokens.
// This enables testing with mock clients.
type IAMGenerateAccessTokener interface {
	GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error)
}

// EndpointHandler serves GCP access tokens via HTTP.
type EndpointHandler struct {
	cfg       *Config
	authToken string // Required auth token for endpoint security

	mu         sync.RWMutex
	cached     *AccessToken
	expiration time.Time

	// iamClient for making GenerateAccessToken calls (injectable for testing)
	iamClient IAMGenerateAccessTokener
}

// NewEndpointHandler creates a new GCP credential endpoint handler.
func NewEndpointHandler(cred *provider.Credential) *EndpointHandler {
	cfg, err := ConfigFromCredential(cred)
	if err != nil {
		// Log error but create handler with minimal config
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
		// Use constant-time comparison to prevent timing attacks
		if auth == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(expectedAuth)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	token, err := h.getAccessToken(r.Context())
	if err != nil {
		// Log detailed error server-side but return generic message to prevent leaking sensitive info
		log.Error("GCP credential fetch error", "error", err)
		http.Error(w, "failed to get credentials", http.StatusInternalServerError)
		return
	}

	// GCP executable-sourced credential output format.
	// See: https://google.aip.dev/auth/4117
	resp := map[string]interface{}{
		"version":         1,
		"success":         true,
		"token_type":      "urn:ietf:params:oauth:token-type:access_token",
		"access_token":    token.Token,
		"expiration_time": token.Expiration.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Response already started, can't send HTTP error. Log and continue.
		ui.Warnf("Failed to encode GCP credentials response: %v", err)
	}
}

// getAccessToken returns a cached access token or fetches a new one via IAM generateAccessToken.
func (h *EndpointHandler) getAccessToken(ctx context.Context) (*AccessToken, error) {
	// Check context before proceeding
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	h.mu.RLock()
	// Return cached if valid with buffer before expiration
	if h.cached != nil && time.Now().Add(credentialRefreshBuffer).Before(h.expiration) {
		token := h.cached
		h.mu.RUnlock()
		return token, nil
	}
	h.mu.RUnlock()

	// Need to refresh
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
		h.iamClient = &iamClientAdapter{client: client}
	}

	// Call IAM GenerateAccessToken
	resp, err := h.iamClient.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name:     fmt.Sprintf("projects/-/serviceAccounts/%s", h.cfg.ServiceAccount),
		Scope:    DefaultScopes,
		Lifetime: durationpb.New(h.cfg.Lifetime),
	})
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

// iamClientAdapter wraps the real IAM credentials client to match the IAMGenerateAccessTokener interface.
type iamClientAdapter struct {
	client *credentials.IamCredentialsClient
}

func (a *iamClientAdapter) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
	return a.client.GenerateAccessToken(ctx, req, opts...)
}
