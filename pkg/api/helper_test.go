package api

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewPodInfo_UID(t *testing.T) {
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "pod1", UID: "uid-1"}}

	podInfo := NewPodInfo(pod, nil, nil, "")

	if podInfo.GetUid() != "uid-1" {
		t.Errorf("NewPodInfo() UID = %q, want %q", podInfo.GetUid(), "uid-1")
	}
}

func TestPodInfo_UIDEncoding(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		podInfo := &PodInfo{Name: "pod1", Namespace: &Namespace{Name: "ns1"}, ClusterId: "cluster", Uid: "uid-1"}
		data, err := proto.Marshal(podInfo)
		if err != nil {
			t.Fatalf("Marshal() failed: %v", err)
		}
		var got PodInfo
		if err := proto.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal() failed: %v", err)
		}
		if !proto.Equal(&got, podInfo) {
			t.Errorf("Unmarshal() = %v, want %v", &got, podInfo)
		}
	})

	t.Run("record written before the UID was added", func(t *testing.T) {
		// The fields 1 and 7 encoded without the field 8.
		var data []byte
		data = protowire.AppendTag(data, 1, protowire.BytesType)
		data = protowire.AppendString(data, "pod1")
		data = protowire.AppendTag(data, 7, protowire.BytesType)
		data = protowire.AppendString(data, "cluster")
		var got PodInfo
		if err := proto.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal() failed: %v", err)
		}
		if got.GetName() != "pod1" || got.GetClusterId() != "cluster" || got.GetUid() != "" {
			t.Errorf("Unmarshal() = %v, want pod1 in cluster without UID", &got)
		}
	})

	t.Run("UID is field 8", func(t *testing.T) {
		data, err := proto.Marshal(&PodInfo{Uid: "uid-1"})
		if err != nil {
			t.Fatalf("Marshal() failed: %v", err)
		}
		number, wireType, n := protowire.ConsumeTag(data)
		value, _ := protowire.ConsumeString(data[n:])
		if number != 8 || wireType != protowire.BytesType || value != "uid-1" {
			t.Errorf("Marshal() = field %d type %d value %q, want field 8 with the UID", number, wireType, value)
		}
	})
}

func TestSamePod(t *testing.T) {
	podInfo := func(namespace, name, uid string) *PodInfo {
		return &PodInfo{Name: name, Namespace: &Namespace{Name: namespace}, Uid: uid}
	}
	tests := []struct {
		name string
		a, b *PodInfo
		want bool
	}{
		{"same UID", podInfo("ns1", "pod1", "uid-1"), podInfo("ns1", "pod1", "uid-1"), true},
		{"same name and another UID", podInfo("ns1", "pod1", "uid-1"), podInfo("ns1", "pod1", "uid-2"), false},
		{"another name and the same UID", podInfo("ns1", "pod1", "uid-1"), podInfo("ns1", "pod2", "uid-1"), true},
		{"first without UID and the same name", podInfo("ns1", "pod1", ""), podInfo("ns1", "pod1", "uid-1"), true},
		{"second without UID and the same name", podInfo("ns1", "pod1", "uid-1"), podInfo("ns1", "pod1", ""), true},
		{"without UID and another name", podInfo("ns1", "pod1", ""), podInfo("ns1", "pod2", "uid-1"), false},
		{"without UID and another namespace", podInfo("ns1", "pod1", ""), podInfo("ns2", "pod1", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SamePod(tt.a, tt.b); got != tt.want {
				t.Errorf("SamePod() = %v, want %v", got, tt.want)
			}
		})
	}
}
