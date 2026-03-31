package cmd

import (
	"testing"
)

func TestIsEnvVarCritical(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"AWS_SECRET_ACCESS_KEY", true},
		{"VAULT_TOKEN", true},
		{"GITHUB_TOKEN", true},
		{"AWS_ACCESS_KEY_ID", false}, // not in the sensitive list
		{"AWS_REGION", false},
		{"TF_VAR_my_password", false}, // TF_VAR_ prefix handled separately
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := isEnvVarCritical(tt.key)
			if got != tt.expected {
				t.Errorf("isEnvVarCritical(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}

func TestIsTfVarWarning(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"aws_secret_key", true},
		{"db_password", true},
		{"api_token", true},
		{"AWS_SECRET_KEY", true},  // case-insensitive
		{"region", false},
		{"environment", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := isTfVarWarning(tt.key)
			if got != tt.expected {
				t.Errorf("isTfVarWarning(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}
