package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/majorcontext/moat/internal/provider"
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
	cred := &provider.Credential{Token: "test@my-project.iam.gserviceaccount.com"}
	env := p.ContainerEnv(cred)
	if env != nil {
		t.Errorf("ContainerEnv() = %v, want nil", env)
	}
}

func TestProvider_ContainerMounts(t *testing.T) {
	p := New()
	cred := &provider.Credential{Token: "test@my-project.iam.gserviceaccount.com"}
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
		name        string
		email       string
		wantProject string
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid email",
			email:       "my-agent@my-project.iam.gserviceaccount.com",
			wantProject: "my-project",
		},
		{
			name:        "valid with hyphens and numbers",
			email:       "agent-123@my-project-456.iam.gserviceaccount.com",
			wantProject: "my-project-456",
		},
		{
			name:    "empty",
			email:   "",
			wantErr: true,
			errMsg:  "service account email is required",
		},
		{
			name:    "missing @",
			email:   "my-agent.my-project.iam.gserviceaccount.com",
			wantErr: true,
			errMsg:  "missing '@'",
		},
		{
			name:    "empty name",
			email:   "@my-project.iam.gserviceaccount.com",
			wantErr: true,
			errMsg:  "empty name before '@'",
		},
		{
			name:    "wrong domain",
			email:   "my-agent@gmail.com",
			wantErr: true,
			errMsg:  "must end with .iam.gserviceaccount.com",
		},
		{
			name:    "missing project",
			email:   "my-agent@.iam.gserviceaccount.com",
			wantErr: true,
			errMsg:  "missing project ID",
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
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseServiceAccount(%q) error = %q, want error containing %q", tt.email, err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseServiceAccount(%q) unexpected error: %v", tt.email, err)
				return
			}
			if cfg.ServiceAccount != tt.email {
				t.Errorf("ParseServiceAccount(%q).ServiceAccount = %q, want %q", tt.email, cfg.ServiceAccount, tt.email)
			}
			if cfg.Project != tt.wantProject {
				t.Errorf("ParseServiceAccount(%q).Project = %q, want %q", tt.email, cfg.Project, tt.wantProject)
			}
			if cfg.Lifetime != DefaultLifetime {
				t.Errorf("ParseServiceAccount(%q).Lifetime = %v, want %v", tt.email, cfg.Lifetime, DefaultLifetime)
			}
		})
	}
}

func TestConfigFromCredential(t *testing.T) {
	t.Run("basic credential", func(t *testing.T) {
		cred := &provider.Credential{
			Token: "test@my-project.iam.gserviceaccount.com",
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
			Token: "test@my-project.iam.gserviceaccount.com",
			Metadata: map[string]string{
				MetaKeyProject:  "other-project",
				MetaKeyLifetime: "30m",
			},
		}
		cfg, err := ConfigFromCredential(cred)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Project != "other-project" {
			t.Errorf("Project = %q, want %q", cfg.Project, "other-project")
		}
		if cfg.Lifetime != 30*time.Minute {
			t.Errorf("Lifetime = %v, want %v", cfg.Lifetime, 30*time.Minute)
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
			Token: "test@my-project.iam.gserviceaccount.com",
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
	t.Run("returns token", func(t *testing.T) {
		expiration := time.Now().Add(1 * time.Hour)
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "test@my-project.iam.gserviceaccount.com",
				Project:        "my-project",
				Lifetime:       1 * time.Hour,
			},
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
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
		if resp["version"] != float64(1) {
			t.Errorf("version = %v, want 1", resp["version"])
		}
		if resp["success"] != true {
			t.Errorf("success = %v, want true", resp["success"])
		}
		if resp["token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
			t.Errorf("token_type = %v, want urn:ietf:params:oauth:token-type:access_token", resp["token_type"])
		}
		if _, ok := resp["expiration_time"]; !ok {
			t.Error("expiration_time missing from response")
		}
	})

	t.Run("returns 500 on error", func(t *testing.T) {
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "test@my-project.iam.gserviceaccount.com",
				Project:        "my-project",
				Lifetime:       1 * time.Hour,
			},
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
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
				ServiceAccount: "test@my-project.iam.gserviceaccount.com",
				Project:        "my-project",
				Lifetime:       1 * time.Hour,
			},
			authToken: "secret-token",
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
					return &credentialspb.GenerateAccessTokenResponse{
						AccessToken: "ya29.test-access-token",
						ExpireTime:  timestamppb.New(time.Now().Add(1 * time.Hour)),
					}, nil
				},
			},
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
				ServiceAccount: "test@my-project.iam.gserviceaccount.com",
				Project:        "my-project",
				Lifetime:       1 * time.Hour,
			},
			authToken: "secret-token",
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
					return &credentialspb.GenerateAccessTokenResponse{
						AccessToken: "ya29.test-access-token",
						ExpireTime:  timestamppb.New(time.Now().Add(1 * time.Hour)),
					}, nil
				},
			},
		}

		req := httptest.NewRequest("GET", "/gcp-credentials", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("returns 200 with valid auth", func(t *testing.T) {
		handler := &EndpointHandler{
			cfg: &Config{
				ServiceAccount: "test@my-project.iam.gserviceaccount.com",
				Project:        "my-project",
				Lifetime:       1 * time.Hour,
			},
			authToken: "secret-token",
			iamClient: &mockIAMClient{
				generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
					return &credentialspb.GenerateAccessTokenResponse{
						AccessToken: "ya29.test-access-token",
						ExpireTime:  timestamppb.New(time.Now().Add(1 * time.Hour)),
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
			ServiceAccount: "test@my-project.iam.gserviceaccount.com",
			Project:        "my-project",
			Lifetime:       1 * time.Hour,
		},
		iamClient: &mockIAMClient{
			generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
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

	// Should return same token
	if token1.Token != token2.Token {
		t.Errorf("cached tokens should match: %q != %q", token1.Token, token2.Token)
	}
}

func TestEndpointHandler_RefreshesExpiredToken(t *testing.T) {
	callCount := 0

	handler := &EndpointHandler{
		cfg: &Config{
			ServiceAccount: "test@my-project.iam.gserviceaccount.com",
			Project:        "my-project",
			Lifetime:       1 * time.Hour,
		},
		iamClient: &mockIAMClient{
			generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
				callCount++
				// Return token that expires within 5 min buffer
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

	// Second call should refresh because token expires within 5 min
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
	generateAccessTokenFn func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error)
}

func (m *mockIAMClient) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
	return m.generateAccessTokenFn(ctx, req, opts...)
}
