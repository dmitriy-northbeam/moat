package gcp

import (
	"context"
	"net/http"

	"github.com/majorcontext/moat/internal/provider"
)

// Provider implements provider.CredentialProvider and provider.EndpointProvider
// for GCP credentials via IAM generateAccessToken.
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
// GCP credentials are served via RegisterEndpoints, not header injection.
func (p *Provider) ConfigureProxy(pc provider.ProxyConfigurer, cred *provider.Credential) {
	// No-op: GCP uses credential endpoint, not proxy header injection
}

// ContainerEnv returns nil; the run manager sets GOOGLE_APPLICATION_CREDENTIALS.
func (p *Provider) ContainerEnv(cred *provider.Credential) []string {
	// The run manager configures GOOGLE_APPLICATION_CREDENTIALS
	// pointing to the external credential config file.
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
// The handler serves temporary access tokens from IAM generateAccessToken.
func (p *Provider) RegisterEndpoints(mux *http.ServeMux, cred *provider.Credential) {
	handler := NewEndpointHandler(cred)
	mux.Handle("/gcp-credentials", handler)
}
