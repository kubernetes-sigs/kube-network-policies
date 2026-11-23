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

package dht

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

const (
	defaultListenAddress = ":19091"
	defaultRecordTTL     = 90 * time.Second
	defaultCacheTTL      = 10 * time.Second
	defaultNegCacheTTL   = 5 * time.Second
	defaultCacheSize     = 4096
	defaultRPCTimeout    = 100 * time.Millisecond
	shutdownTimeout      = 2 * time.Second
	tombstoneRetryDelay  = 1 * time.Second
)

// Config configures a pure 1-hop DHT node with no Kubernetes dependencies.
type Config struct {
	NodeName          string
	ListenAddress     string
	ReplicationFactor int
	RecordTTL         time.Duration
	CacheTTL          time.Duration
	NegativeCacheTTL  time.Duration
	CacheSize         int
	RPCTimeout        time.Duration
	ServerTLS         *tls.Config
	ClientTLS         *tls.Config
	// RequireNodeCert rejects mTLS Put requests whose client certificate does
	// not carry CN=system:node:<nodeName>.
	RequireNodeCert bool
	// Now allows tests to inject a deterministic clock.
	Now func() time.Time
}

// Defaults fills unset Config fields with production defaults.
func (c *Config) Defaults() {
	if c.ListenAddress == "" {
		c.ListenAddress = defaultListenAddress
	}
	if c.ReplicationFactor <= 0 {
		c.ReplicationFactor = DefaultReplicationFactor
	}
	if c.RecordTTL <= 0 {
		c.RecordTTL = defaultRecordTTL
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = defaultCacheTTL
	}
	if c.NegativeCacheTTL <= 0 {
		c.NegativeCacheTTL = defaultNegCacheTTL
	}
	if c.CacheSize <= 0 {
		c.CacheSize = defaultCacheSize
	}
	if c.RPCTimeout <= 0 {
		c.RPCTimeout = defaultRPCTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Validate checks Config for invalid values.
func (c *Config) Validate() error {
	if c.NodeName == "" {
		return errors.New("dht config: NodeName is required")
	}
	if c.ReplicationFactor < 1 {
		return fmt.Errorf("dht config: ReplicationFactor must be >= 1, got %d", c.ReplicationFactor)
	}
	return nil
}

// DHT implements a self-contained 1-hop Rendezvous-Hashing DHT over stdlib
// HTTP/2 (h2c or TLS 1.3 mTLS). Callers publish local pod IPs via non-blocking
// Publish/Delete calls and resolve remote IPs via Lookup or GetPodInfoByIP.
type DHT struct {
	cfg    Config
	ring   atomic.Pointer[Ring]
	store  *Store
	cache  *ReaderCache
	client *http.Client
	sf     singleflight.Group
	seq    atomic.Uint64

	listenAddr atomic.Pointer[string]

	// Single-writer async publishing state. Informer and NRI callbacks only
	// mutate these maps under pubMu and signal publishCh; only publishLoop
	// allocates sequence numbers and performs network I/O.
	pubMu      sync.Mutex
	live       map[string]*api.PodInfo
	tombstones map[string]time.Time // ip -> expiry; retried until all replicas ACK
	dirty      map[string]struct{}
	publishCh  chan struct{}
	fullSyncCh chan struct{}
}

var _ api.PodInfoProvider = &DHT{}
var _ api.PodInfoResolver = &DHT{}

// New creates a new 1-hop DHT instance. Call Run(ctx) to start serving and
// background publishing/GC loops.
func New(cfg Config) (*DHT, error) {
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	registerMetrics()

	d := &DHT{
		cfg:        cfg,
		store:      NewStore(defaultMaxStoreRecords),
		cache:      NewReaderCache(cfg.CacheSize),
		client:     newHTTPClient(cfg.ClientTLS),
		live:       make(map[string]*api.PodInfo),
		tombstones: make(map[string]time.Time),
		dirty:      make(map[string]struct{}),
		publishCh:  make(chan struct{}, 1),
		fullSyncCh: make(chan struct{}, 1),
	}
	// Seed sequence from current wall clock (clamped >= 1 so pre-1970 RTC never
	// underflows uint64). If NTP steps backward across a restart, replicas return
	// MaxSeq so publishLoop advances past it automatically.
	if ns := cfg.Now().UnixNano(); ns > 0 {
		d.seq.Store(uint64(ns))
	} else {
		d.seq.Store(1)
	}
	d.ring.Store(NewRing(nil))
	return d, nil
}

// Run opens the HTTP/2 listener, serves Put/Get requests, and runs the async
// publisher and GC loops until ctx is cancelled.
func (d *DHT) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", d.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("dht listen on %s: %w", d.cfg.ListenAddress, err)
	}
	if d.cfg.ServerTLS != nil {
		lis = tls.NewListener(lis, d.cfg.ServerTLS.Clone())
	}

	addr := lis.Addr().String()
	d.listenAddr.Store(&addr)

	srv := newHTTPServer(d.routes(), d.cfg.ServerTLS)
	defer d.client.CloseIdleConnections()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		d.publishLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		d.gcLoop(ctx)
	}()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errCh:
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		_ = srv.Close()
	}
	wg.Wait()
	return serveErr
}

// ListenAddr returns the bound host:port once Run has opened its listener.
func (d *DHT) ListenAddr() string {
	if p := d.listenAddr.Load(); p != nil {
		return *p
	}
	return ""
}

// UpdateMembers atomically swaps the active Rendezvous Hashing ring and
// schedules an async rebalance publish if membership changed. Existing replica
// records are NOT evicted on membership change so DaemonSet rolling updates
// never blackhole healthy workload pods; RecordTTL expires dead nodes naturally.
func (d *DHT) UpdateMembers(members []Member) {
	newRing := NewRing(members)
	dhtRingMembers.Set(float64(newRing.Len()))

	oldRing := d.ring.Load()
	if oldRing.Equal(newRing) {
		return
	}
	d.ring.Store(newRing)

	select {
	case d.fullSyncCh <- struct{}{}:
	default:
	}
}

// Publish registers or updates a local pod IP and schedules a non-blocking
// batched Put to its R replicas. Safe to call from informer and NRI callbacks.
func (d *DHT) Publish(ip string, pod *api.PodInfo) {
	if ip == "" || pod == nil {
		return
	}
	cloned := proto.Clone(pod).(*api.PodInfo)
	cloned.Node = &api.Node{Name: d.cfg.NodeName}
	if cloned.Namespace != nil {
		cloned.Namespace = &api.Namespace{Name: cloned.Namespace.Name}
	}
	d.cache.Delete(ip)

	d.pubMu.Lock()
	d.live[ip] = cloned
	delete(d.tombstones, ip)
	d.dirty[ip] = struct{}{}
	d.pubMu.Unlock()

	select {
	case d.publishCh <- struct{}{}:
	default:
	}
}

// Delete releases a local pod IP and schedules a non-blocking tombstone Put
// (retried until replicas acknowledge or RecordTTL elapses). Safe to call from
// informer and NRI callbacks.
func (d *DHT) Delete(ip string) {
	if ip == "" {
		return
	}
	d.cache.Delete(ip)

	d.pubMu.Lock()
	delete(d.live, ip)
	d.tombstones[ip] = d.cfg.Now().Add(d.cfg.RecordTTL)
	d.dirty[ip] = struct{}{}
	d.pubMu.Unlock()

	select {
	case d.publishCh <- struct{}{}:
	default:
	}
}

// GetPodInfoByIP implements api.PodInfoProvider (ignoring transient errors).
func (d *DHT) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	pod, found, err := d.ResolvePodInfoByIP(context.Background(), ip)
	if err != nil {
		return nil, false
	}
	return pod, found
}

// ResolvePodInfoByIP implements api.PodInfoResolver. It resolves remote IPs
// through the bounded TTL/LRU cache and singleflight sequential 1-hop fallback
// across up to ReplicationFactor replicas. Transient RPC errors are returned
// directly (and not negative-cached) so callers can honor FailOpen policy.
func (d *DHT) ResolvePodInfoByIP(ctx context.Context, ip string) (*api.PodInfo, bool, error) {
	now := d.cfg.Now()
	if cached, found, hit := d.cache.Get(ip, now); hit {
		if found {
			dhtLookupsTotal.WithLabelValues("cache_hit").Inc()
			return cached, true, nil
		}
		dhtLookupsTotal.WithLabelValues("cache_neg_hit").Inc()
		return nil, false, nil
	}

	type lookupRes struct {
		pod   *api.PodInfo
		found bool
	}
	v, err, _ := d.sf.Do(ip, func() (any, error) {
		pod, found, err := d.lookupRing(ctx, ip)
		return lookupRes{pod: pod, found: found}, err
	})
	if err != nil {
		dhtLookupsTotal.WithLabelValues("remote_error").Inc()
		return nil, false, err
	}
	res := v.(lookupRes)
	return res.pod, res.found, nil
}

func (d *DHT) lookupRing(ctx context.Context, ip string) (*api.PodInfo, bool, error) {
	now := d.cfg.Now()
	if cached, found, hit := d.cache.Get(ip, now); hit {
		return cached, found, nil
	}

	ring := d.ring.Load()
	targets := ring.Targets(ip, d.cfg.ReplicationFactor)
	if len(targets) == 0 {
		return nil, false, nil
	}

	perTry := max(d.cfg.RPCTimeout/time.Duration(len(targets)), 10*time.Millisecond)
	var allRecords []Record
	var lastErr error
	anyErr := false

	for i, target := range targets {
		var recs []Record
		var err error
		if target.NodeName == d.cfg.NodeName {
			recs = d.store.Get(ip, d.cfg.Now())
		} else {
			tCtx, cancel := context.WithTimeout(ctx, perTry)
			recs, err = d.remoteGet(tCtx, target.Address, ip)
			cancel()
		}
		if err != nil {
			anyErr = true
			lastErr = err
			continue
		}
		allRecords = append(allRecords, recs...)

		// Happy path: if the primary replica returned a live record with no
		// tombstone, return in 1 RTT without querying additional replicas.
		if i == 0 && len(recs) > 0 && !hasTombstone(recs) {
			pod, found, err := ResolveRecords(recs)
			if err != nil {
				return nil, false, err
			}
			if found {
				if target.NodeName == d.cfg.NodeName {
					dhtLookupsTotal.WithLabelValues("replica_local").Inc()
				} else {
					dhtLookupsTotal.WithLabelValues("remote_hit").Inc()
				}
				d.cache.SetPositive(ip, pod, d.cfg.CacheTTL, d.cfg.Now())
				return pod, true, nil
			}
		}
	}

	pod, found, err := ResolveRecords(allRecords)
	if err != nil {
		return nil, false, err
	}
	if found {
		dhtLookupsTotal.WithLabelValues("remote_hit").Inc()
		d.cache.SetPositive(ip, pod, d.cfg.CacheTTL, d.cfg.Now())
		return pod, true, nil
	}

	// If every replica succeeded with no active record (or a tombstone
	// suppressed stale records), cache the definitive miss. If any replica
	// errored and no tombstone proved deletion, propagate the error for FailOpen.
	if anyErr && !hasTombstone(allRecords) {
		return nil, false, lastErr
	}
	dhtLookupsTotal.WithLabelValues("remote_miss").Inc()
	d.cache.SetNegative(ip, d.cfg.NegativeCacheTTL, d.cfg.Now())
	return nil, false, nil
}

func (d *DHT) publishLoop(ctx context.Context) {
	refreshInterval := max(d.cfg.RecordTTL/3, 50*time.Millisecond)
	refreshTicker := time.NewTicker(refreshInterval)
	retryTicker := time.NewTicker(tombstoneRetryDelay)
	defer refreshTicker.Stop()
	defer retryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.publishCh:
			d.flushDirty(ctx)
		case <-d.fullSyncCh:
			d.flushAll(ctx)
		case <-refreshTicker.C:
			d.flushAll(ctx)
		case <-retryTicker.C:
			d.retryTombstones(ctx)
		}
	}
}

func (d *DHT) gcLoop(ctx context.Context) {
	gcInterval := max(d.cfg.RecordTTL/2, 50*time.Millisecond)
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dhtStoreRecords.Set(float64(d.store.GC(d.cfg.Now())))
		}
	}
}

func (d *DHT) flushDirty(ctx context.Context) {
	d.pubMu.Lock()
	if len(d.dirty) == 0 {
		d.pubMu.Unlock()
		return
	}
	ips := make([]string, 0, len(d.dirty))
	for ip := range d.dirty {
		ips = append(ips, ip)
	}
	clear(d.dirty)
	recs := d.buildRecordsLocked(ips)
	d.pubMu.Unlock()

	d.sendRecords(ctx, recs)
}

func (d *DHT) flushAll(ctx context.Context) {
	now := d.cfg.Now()
	d.pubMu.Lock()
	clear(d.dirty)
	ips := make([]string, 0, len(d.live)+len(d.tombstones))
	for ip := range d.live {
		ips = append(ips, ip)
	}
	for ip, exp := range d.tombstones {
		if !exp.After(now) {
			delete(d.tombstones, ip)
			continue
		}
		ips = append(ips, ip)
	}
	recs := d.buildRecordsLocked(ips)
	d.pubMu.Unlock()

	d.sendRecords(ctx, recs)
}

func (d *DHT) retryTombstones(ctx context.Context) {
	now := d.cfg.Now()
	d.pubMu.Lock()
	var ips []string
	for ip, exp := range d.tombstones {
		if !exp.After(now) {
			delete(d.tombstones, ip)
			continue
		}
		ips = append(ips, ip)
	}
	recs := d.buildRecordsLocked(ips)
	d.pubMu.Unlock()

	d.sendRecords(ctx, recs)
}

// buildRecordsLocked creates wire Records from the authoritative local state
// and assigns monotonically increasing sequence numbers strictly under pubMu
// so concurrent refreshes and deletes can never invert Seq order.
func (d *DHT) buildRecordsLocked(ips []string) []Record {
	if len(ips) == 0 {
		return nil
	}
	ttlMS := d.cfg.RecordTTL.Milliseconds()
	recs := make([]Record, 0, len(ips))
	for _, ip := range ips {
		if pod, ok := d.live[ip]; ok {
			pb, err := proto.Marshal(pod)
			if err != nil {
				klog.ErrorS(err, "marshaling local pod_info for DHT", "ip", ip)
				continue
			}
			recs = append(recs, Record{
				IP:        ip,
				OwnerNode: d.cfg.NodeName,
				Seq:       d.seq.Add(1),
				TTLMS:     ttlMS,
				PodInfoPB: pb,
			})
			continue
		}
		if _, ok := d.tombstones[ip]; ok {
			recs = append(recs, Record{
				IP:        ip,
				OwnerNode: d.cfg.NodeName,
				Seq:       d.seq.Add(1),
				Tombstone: true,
				TTLMS:     ttlMS,
			})
		}
	}
	return recs
}

func (d *DHT) sendRecords(ctx context.Context, records []Record) {
	if len(records) == 0 {
		return
	}
	ring := d.ring.Load()
	byTarget := make(map[Member][]Record)
	for _, rec := range records {
		targets := ring.Targets(rec.IP, d.cfg.ReplicationFactor)
		if len(targets) == 0 {
			// Store locally before membership syncs so single-node / bootstrap state is kept.
			self := Member{NodeName: d.cfg.NodeName}
			byTarget[self] = append(byTarget[self], rec)
			continue
		}
		for _, t := range targets {
			byTarget[t] = append(byTarget[t], rec)
		}
	}

	var failedMu sync.Mutex
	failedIPs := make(map[string]struct{})
	var maxObservedSeq atomic.Uint64

	var wg sync.WaitGroup
	for target, batch := range byTarget {
		if target.NodeName == d.cfg.NodeName {
			now := d.cfg.Now()
			for _, rec := range batch {
				accepted, existingSeq, err := d.store.Put(rec, now)
				if err != nil {
					klog.V(3).InfoS("DHT local store Put error", "ip", rec.IP, "err", err)
					continue
				}
				if accepted {
					d.cache.Delete(rec.IP)
				} else if existingSeq > 0 {
					updateMax(&maxObservedSeq, existingSeq)
					failedMu.Lock()
					failedIPs[rec.IP] = struct{}{}
					failedMu.Unlock()
				}
			}
			dhtStoreRecords.Set(float64(d.store.Len()))
			continue
		}

		wg.Add(1)
		go func(addr string, recs []Record) {
			defer wg.Done()
			for start := 0; start < len(recs); start += maxBatchRecords {
				end := min(start+maxBatchRecords, len(recs))
				chunk := recs[start:end]
				rpcCtx, cancel := context.WithTimeout(ctx, d.cfg.RPCTimeout)
				maxSeqMap, err := d.remotePut(rpcCtx, addr, chunk)
				cancel()
				if err != nil {
					klog.V(3).InfoS("DHT Put failed", "target", addr, "count", len(chunk), "err", err)
					failedMu.Lock()
					for _, r := range chunk {
						failedIPs[r.IP] = struct{}{}
					}
					failedMu.Unlock()
					continue
				}
				for ip, seq := range maxSeqMap {
					updateMax(&maxObservedSeq, seq)
					failedMu.Lock()
					failedIPs[ip] = struct{}{}
					failedMu.Unlock()
				}
			}
		}(target.Address, batch)
	}
	wg.Wait()

	// If any replica rejected a stale Seq (for example after a backward NTP
	// step on agent restart), advance our monotonic counter past it.
	if maxSeq := maxObservedSeq.Load(); maxSeq > 0 {
		updateMax(&d.seq, maxSeq)
	}

	// Clear tombstones that ALL replicas acknowledged cleanly; keep failed
	// tombstones so retryTicker retries them until ACKed or TTL expires.
	d.pubMu.Lock()
	for _, rec := range records {
		if _, failed := failedIPs[rec.IP]; failed {
			continue
		}
		if rec.Tombstone {
			delete(d.tombstones, rec.IP)
		}
	}
	// Re-queue only records that hit a sequence-bump rejection so they retry immediately.
	if maxObservedSeq.Load() > 0 && len(failedIPs) > 0 {
		for ip := range failedIPs {
			d.dirty[ip] = struct{}{}
		}
		select {
		case d.publishCh <- struct{}{}:
		default:
		}
	}
	d.pubMu.Unlock()
}

func hasTombstone(recs []Record) bool {
	for _, r := range recs {
		if r.Tombstone {
			return true
		}
	}
	return false
}

func updateMax(target *atomic.Uint64, val uint64) {
	for {
		cur := target.Load()
		if val <= cur {
			return
		}
		if target.CompareAndSwap(cur, val) {
			return
		}
	}
}
