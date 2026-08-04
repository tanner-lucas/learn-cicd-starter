package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    error
	}{
		{
			name:       "valid header",
			authHeader: "ApiKey my-secret-key",
			wantKey:    "my-secret-key",
			wantErr:    nil,
		},
		{
			name:       "no auth header",
			authHeader: "",
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "wrong scheme",
			authHeader: "Bearer my-secret-key",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "missing key",
			authHeader: "ApiKey",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			gotKey, gotErr := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			if tt.wantErr == nil {
				if gotErr != nil {
					t.Errorf("GetAPIKey() unexpected error: %v", gotErr)
				}
				return
			}
			if gotErr == nil {
				t.Errorf("GetAPIKey() expected error %q, got nil", tt.wantErr)
				return
			}
			if gotErr.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %q, want %q", gotErr, tt.wantErr)
			}
		})
	}
}
