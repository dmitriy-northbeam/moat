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
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGCPCredentialHandler_ServeHTTP(t *testing.T) {
	t.Run("returns token", func(t *testing.T) {
		expiration := time.Now().Add(15 * time.Minute).Truncate(time.Second)
		handler := &GCPCredentialHandler{
			getCredentials: func(ctx context.Context) (*GCPAccessToken, error) {
				return &GCPAccessToken{
					Token:      "ya29.example-access-token",
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

		if resp["access_token"] != "ya29.example-access-token" {
			t.Errorf("access_token = %v, want ya29.example-access-token", resp["access_token"])
		}
		if resp["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", resp["token_type"])
		}
		if _, ok := resp["expires_in"]; !ok {
			t.Error("expires_in missing from response")
		}
		if _, ok := resp["expiry"]; !ok {
			t.Error("expiry missing from response")
		}
	})

	t.Run("returns 500 on error", func(t *testing.T) {
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
				return &GCPAccessToken{
					Token:      "ya29.example-access-token",
					Expiration: time.Now().Add(15 * time.Minute),
				}, nil
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
				return &GCPAccessToken{
					Token:      "ya29.example-access-token",
					Expiration: time.Now().Add(15 * time.Minute),
				}, nil
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

	t.Run("returns 200 with valid auth", func(t *testing.T) {
		handler := &GCPCredentialHandler{
			getCredentials: func(ctx context.Context) (*GCPAccessToken, error) {
				return &GCPAccessToken{
					Token:      "ya29.example-access-token",
					Expiration: time.Now().Add(15 * time.Minute),
				}, nil
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

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp["access_token"] != "ya29.example-access-token" {
			t.Errorf("access_token = %v, want ya29.example-access-token", resp["access_token"])
		}
	})
}

func TestGCPCredentialProvider_Caching(t *testing.T) {
	callCount := 0
	expiration := time.Now().Add(15 * time.Minute)

	mockIAM := &mockProxyIAMClient{
		generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
			callCount++
			return &credentialspb.GenerateAccessTokenResponse{
				AccessToken: fmt.Sprintf("ya29.token-%d", callCount),
				ExpireTime:  timestamppb.New(expiration),
			}, nil
		},
	}

	provider := &GCPCredentialProvider{
		serviceAccount: "test@project.iam.gserviceaccount.com",
		project:        "test-project",
		lifetime:       time.Hour,
		iamClient:      mockIAM,
	}

	// First call should hit IAM
	creds1, err := provider.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	// Second call should use cache
	creds2, err := provider.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1 (cached)", callCount)
	}

	// Should return same credentials
	if creds1.Token != creds2.Token {
		t.Errorf("cached credentials should match")
	}
}

func TestGCPCredentialProvider_RefreshesExpiredCredentials(t *testing.T) {
	callCount := 0

	mockIAM := &mockProxyIAMClient{
		generateAccessTokenFn: func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
			callCount++
			// Return credentials that expire soon (within 5 min buffer)
			expiration := time.Now().Add(3 * time.Minute)
			return &credentialspb.GenerateAccessTokenResponse{
				AccessToken: fmt.Sprintf("ya29.token-%d", callCount),
				ExpireTime:  timestamppb.New(expiration),
			}, nil
		},
	}

	provider := &GCPCredentialProvider{
		serviceAccount: "test@project.iam.gserviceaccount.com",
		project:        "test-project",
		lifetime:       time.Hour,
		iamClient:      mockIAM,
	}

	// First call
	_, err := provider.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	// Second call should refresh because credentials expire within 5 min
	_, err = provider.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("callCount = %d, want 2 (should refresh near-expiry credentials)", callCount)
	}
}

type mockProxyIAMClient struct {
	generateAccessTokenFn func(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error)
}

func (m *mockProxyIAMClient) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
	return m.generateAccessTokenFn(ctx, req, opts...)
}
