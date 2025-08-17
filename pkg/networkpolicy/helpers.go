package networkpolicy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

// MatchesSelector returns true if the selector matches the given labels.
func MatchesSelector(selector *metav1.LabelSelector, lbls map[string]string) bool {
	s, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		klog.Errorf("error parsing label selector: %v", err)
		return false
	}
	return s.Matches(labels.Set(lbls))
}
