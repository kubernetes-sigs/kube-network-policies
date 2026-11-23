/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dataplane

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

type recordedVerdict struct {
	id      uint32
	verdict int
}

type fakeVerdictSetter struct {
	mu       sync.Mutex
	verdicts map[uint32]int
	ch       chan recordedVerdict
}

func newFakeVerdictSetter() *fakeVerdictSetter {
	return &fakeVerdictSetter{
		verdicts: make(map[uint32]int),
		ch:       make(chan recordedVerdict, 64),
	}
}

func (f *fakeVerdictSetter) SetVerdict(id uint32, verdict int) error {
	return f.record(id, verdict)
}

func (f *fakeVerdictSetter) SetVerdictWithOption(id uint32, verdict int, _ ...nfqueue.VerdictOption) error {
	return f.record(id, verdict)
}

func (f *fakeVerdictSetter) record(id uint32, verdict int) error {
	f.mu.Lock()
	f.verdicts[id] = verdict
	f.mu.Unlock()
	f.ch <- recordedVerdict{id: id, verdict: verdict}
	return nil
}

// buildIPv4TCPPacket constructs a minimal valid 40-byte IPv4 + TCP header.
func buildIPv4TCPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	buf := make([]byte, 40)
	buf[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64 // TTL
	buf[9] = unix.IPPROTO_TCP
	copy(buf[12:16], net.ParseIP(srcIP).To4())
	copy(buf[16:20], net.ParseIP(dstIP).To4())
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	buf[32] = 0x50 // TCP data offset = 5 (20 bytes)
	return buf
}

func TestController_AsyncDispatchUnit(t *testing.T) {
	slowStarted := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})

	evaluators := []api.PolicyEvaluator{
		&mockPolicyEvaluator{
			name:      "async-unit-evaluator",
			divertAll: true,
			isReady:   true,
			evaluateEgress: func(_ context.Context, p *network.Packet, _, _ *api.PodInfo) (api.Verdict, error) {
				switch p.DstPort {
				case 8080:
					select {
					case slowStarted <- struct{}{}:
					default:
					}
					<-releaseSlow
					return api.VerdictAccept, nil
				case 8081:
					return api.VerdictAccept, nil
				default:
					return api.VerdictDeny, nil
				}
			},
		},
	}

	cfg := Config{
		FailOpen:     false,
		QueueID:      100,
		AsyncWorkers: 2,
	}
	if err := cfg.Defaults(); err != nil {
		t.Fatalf("Defaults() error = %v", err)
	}
	c := newTestController(cfg, evaluators)
	sink := newFakeVerdictSetter()
	c.nfq = sink

	workerCtx, workCh, stopWorkers := c.startAsyncWorkers(context.Background(), 16)
	defer stopWorkers()
	handler := c.newPacketHandler(workerCtx, workCh)

	// 1. Dispatch slow packet (id=1, port 8080). Handler must return immediately.
	slowPayload := buildIPv4TCPPacket("10.0.0.1", "10.0.0.2", 40000, 8080)
	id1 := uint32(1)
	handler(nfqueue.Attribute{PacketID: &id1, Payload: &slowPayload})

	select {
	case <-slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for slow packet to enter worker")
	}

	// 2. While worker 1 is blocked on packet 1, packet 2 (accept) and packet 3 (deny)
	// must complete on worker 2 without head-of-line blocking.
	fastPayload := buildIPv4TCPPacket("10.0.0.1", "10.0.0.3", 40001, 8081)
	id2 := uint32(2)
	handler(nfqueue.Attribute{PacketID: &id2, Payload: &fastPayload})

	denyPayload := buildIPv4TCPPacket("10.0.0.1", "10.0.0.4", 40002, 9999)
	id3 := uint32(3)
	handler(nfqueue.Attribute{PacketID: &id3, Payload: &denyPayload})

	got := map[uint32]int{}
	for len(got) < 2 {
		select {
		case rv := <-sink.ch:
			got[rv.id] = rv.verdict
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for fast packets while slow packet blocked, got %v", got)
		}
	}
	if got[2] != nfqueue.NfAccept || got[3] != nfqueue.NfDrop {
		t.Fatalf("unexpected verdicts for fast packets: %v", got)
	}

	// 3. Corrupt payload gets immediate default verdict (FailOpen=false -> Drop).
	badPayload := []byte{0x01, 0x02}
	id4 := uint32(4)
	handler(nfqueue.Attribute{PacketID: &id4, Payload: &badPayload})
	select {
	case rv := <-sink.ch:
		if rv.id != 4 || rv.verdict != nfqueue.NfDrop {
			t.Fatalf("corrupt packet verdict = %+v, want {id:4 NfDrop}", rv)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for corrupt packet verdict")
	}

	// 4. Release slow packet and verify it finishes cleanly.
	close(releaseSlow)
	select {
	case rv := <-sink.ch:
		if rv.id != 1 || rv.verdict != nfqueue.NfAccept {
			t.Fatalf("slow packet verdict = %+v, want {id:1 NfAccept}", rv)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for slow packet verdict")
	}
}

func TestController_AsyncQueueOverflowAppliesDefaultVerdict(t *testing.T) {
	cfg := Config{
		FailOpen:     true,
		QueueID:      100,
		AsyncWorkers: 1,
	}
	_ = cfg.Defaults()
	c := newTestController(cfg, nil)
	sink := newFakeVerdictSetter()
	c.nfq = sink

	// Create a full channel with capacity 1 and no workers draining it.
	fullCh := make(chan asyncPacketItem, 1)
	fullCh <- asyncPacketItem{}
	handler := c.newPacketHandler(context.Background(), fullCh)

	payload := buildIPv4TCPPacket("10.0.0.1", "10.0.0.2", 40000, 80)
	id := uint32(7)
	handler(nfqueue.Attribute{PacketID: &id, Payload: &payload})

	select {
	case rv := <-sink.ch:
		if rv.id != 7 || rv.verdict != nfqueue.NfAccept {
			t.Fatalf("overflow verdict with FailOpen=true = %+v, want NfAccept", rv)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for overflow default verdict")
	}
}

func TestConfig_ValidateAsyncWorkers(t *testing.T) {
	cfg := Config{AsyncWorkers: -1}
	_ = cfg.Defaults()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for negative AsyncWorkers")
	}
}
