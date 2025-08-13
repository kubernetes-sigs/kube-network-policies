package networkpolicy

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestMatchesSelector contains the unit tests.
func TestMatchesSelector(t *testing.T) {
	// Define the test table
	tests := []struct {
		name     string
		selector *metav1.LabelSelector
		labels   map[string]string
		want     bool
	}{
		{
			name:     "nil selector should not match",
			selector: nil,
			labels:   map[string]string{"app": "test"},
			want:     false,
		},
		{
			name:     "empty selector matches any labels",
			selector: &metav1.LabelSelector{},
			labels:   map[string]string{"app": "test"},
			want:     true,
		},
		{
			name:     "empty selector matches empty labels",
			selector: &metav1.LabelSelector{},
			labels:   map[string]string{},
			want:     true,
		},
		{
			name:     "empty selector matches nil labels",
			selector: &metav1.LabelSelector{},
			labels:   nil,
			want:     true,
		},
		{
			name:     "MatchLabels: simple match",
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
			labels:   map[string]string{"app": "test"},
			want:     true,
		},
		{
			name:     "MatchLabels: subset match",
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
			labels:   map[string]string{"app": "test", "env": "prod"},
			want:     true,
		},
		{
			name:     "MatchLabels: multi-label match",
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test", "env": "prod"}},
			labels:   map[string]string{"app": "test", "env": "prod"},
			want:     true,
		},
		{
			name:     "MatchLabels: value mismatch",
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
			labels:   map[string]string{"app": "wrong"},
			want:     false,
		},
		{
			name:     "MatchLabels: key missing",
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
			labels:   map[string]string{"environment": "prod"},
			want:     false,
		},
		{
			name:     "MatchLabels: label empty",
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
			labels:   map[string]string{},
			want:     false,
		},
		{
			name:     "MatchLabels: label missing",
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
			labels:   nil,
			want:     false,
		},
		{
			name: "MatchExpressions: 'In' operator match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend", "backend"}},
			}},
			labels: map[string]string{"tier": "frontend"},
			want:   true,
		},
		{
			name: "MatchExpressions: 'In' operator no match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend", "backend"}},
			}},
			labels: map[string]string{"tier": "database"},
			want:   false,
		},
		{
			name: "MatchExpressions: 'NotIn' operator match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"frontend", "backend"}},
			}},
			labels: map[string]string{"tier": "database"},
			want:   true,
		},
		{
			name: "MatchExpressions: 'NotIn' operator no match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"frontend", "backend"}},
			}},
			labels: map[string]string{"tier": "frontend"},
			want:   false,
		},
		{
			name: "MatchExpressions: 'Exists' operator match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpExists},
			}},
			labels: map[string]string{"env": "production"},
			want:   true,
		},
		{
			name: "MatchExpressions: 'Exists' operator no match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpExists},
			}},
			labels: map[string]string{"app": "test"},
			want:   false,
		},
		{
			name: "MatchExpressions: 'DoesNotExist' operator match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpDoesNotExist},
			}},
			labels: map[string]string{"app": "test"},
			want:   true,
		},
		{
			name: "MatchExpressions: 'DoesNotExist' operator no match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpDoesNotExist},
			}},
			labels: map[string]string{"app": "test", "env": "prod"},
			want:   false,
		},
		{
			name: "Combined: MatchLabels and MatchExpressions both match",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "database"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"cache", "storage"}},
				},
			},
			labels: map[string]string{"app": "database", "tier": "storage"},
			want:   true,
		},
		{
			name: "Combined: MatchLabels fail",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "database"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"cache", "storage"}},
				},
			},
			labels: map[string]string{"app": "wrong", "tier": "storage"},
			want:   false,
		},
		{
			name: "Combined: MatchExpressions fail",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "database"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"cache", "storage"}},
				},
			},
			labels: map[string]string{"app": "database", "tier": "frontend"},
			want:   false,
		},
		{
			name: "Invalid operator should not match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: "bad-operator", Values: []string{"val"}},
			}},
			labels: map[string]string{"tier": "val"},
			want:   false, // Fails because LabelSelectorAsSelector returns an error
		},
	}

	// Run the tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesSelector(tt.selector, tt.labels); got != tt.want {
				t.Errorf("matchesSelector() = %v, want %v", got, tt.want)
			}
		})
	}
}
