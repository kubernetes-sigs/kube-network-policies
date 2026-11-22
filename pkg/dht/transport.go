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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	recordsPath     = "/v1/records"
	maxBodyBytes    = 1 << 20 // 1 MiB
	maxBatchRecords = 256
)

type putRequest struct {
	Records []Record `json:"records"`
}

type putResponse struct {
	// MaxSeq maps IP -> existing sequence number for any record rejected as stale.
	MaxSeq map[string]uint64 `json:"max_seq,omitempty"`
}

type getResponse struct {
	Records []Record `json:"records,omitempty"`
}

// NewTLSConfigs loads mutual-TLS server and client configurations from PEM files.
// Both enforce TLS 1.3 and verify peer certificates against caFile.
func NewTLSConfigs(caFile, certFile, keyFile string) (serverTLS, clientTLS *tls.Config, err error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("loading TLS key pair: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading TLS CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("parsing TLS CA certificate from %s", caFile)
	}

	serverTLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	clientTLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}
	return serverTLS, clientTLS, nil
}

func newHTTPClient(clientTLS *tls.Config) *http.Client {
	protocols := new(http.Protocols)
	tr := &http.Transport{
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	if clientTLS != nil {
		tr.TLSClientConfig = clientTLS.Clone()
		protocols.SetHTTP2(true)
		protocols.SetHTTP1(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}
	tr.Protocols = protocols
	return &http.Client{Transport: tr}
}

func newHTTPServer(handler http.Handler, serverTLS *tls.Config) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	if serverTLS != nil {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}
	srv := &http.Server{
		Handler:           handler,
		Protocols:         protocols,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if serverTLS != nil {
		srv.TLSConfig = serverTLS.Clone()
	}
	return srv
}

func (d *DHT) scheme() string {
	if d.cfg.ClientTLS != nil {
		return "https"
	}
	return "http"
}

func (d *DHT) remotePut(ctx context.Context, addr string, recs []Record) (map[string]uint64, error) {
	start := time.Now()
	body, err := json.Marshal(putRequest{Records: recs})
	if err != nil {
		return nil, err
	}
	reqURL := fmt.Sprintf("%s://%s%s", d.scheme(), addr, recordsPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		dhtRPCDurationSeconds.WithLabelValues("put", "error").Observe(time.Since(start).Seconds())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dhtRPCDurationSeconds.WithLabelValues("put", "error").Observe(time.Since(start).Seconds())
		return nil, fmt.Errorf("PUT %s returned status %d", addr, resp.StatusCode)
	}
	var out putResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxBodyBytes)).Decode(&out); err != nil {
		dhtRPCDurationSeconds.WithLabelValues("put", "error").Observe(time.Since(start).Seconds())
		return nil, err
	}
	dhtRPCDurationSeconds.WithLabelValues("put", "ok").Observe(time.Since(start).Seconds())
	return out.MaxSeq, nil
}

func (d *DHT) remoteGet(ctx context.Context, addr, ip string) ([]Record, error) {
	start := time.Now()
	reqURL := fmt.Sprintf("%s://%s%s?ip=%s", d.scheme(), addr, recordsPath, url.QueryEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		dhtRPCDurationSeconds.WithLabelValues("get", "error").Observe(time.Since(start).Seconds())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dhtRPCDurationSeconds.WithLabelValues("get", "error").Observe(time.Since(start).Seconds())
		return nil, fmt.Errorf("GET %s returned status %d", addr, resp.StatusCode)
	}
	var out getResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxBodyBytes)).Decode(&out); err != nil {
		dhtRPCDurationSeconds.WithLabelValues("get", "error").Observe(time.Since(start).Seconds())
		return nil, err
	}
	dhtRPCDurationSeconds.WithLabelValues("get", "ok").Observe(time.Since(start).Seconds())
	return out.Records, nil
}

func (d *DHT) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(recordsPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			d.handlePut(w, r)
		case http.MethodGet:
			d.handleGet(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux
}

func (d *DHT) handlePut(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req putRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid body: %v", err), http.StatusBadRequest)
		return
	}
	if len(req.Records) > maxBatchRecords {
		http.Error(w, fmt.Sprintf("batch size %d exceeds max %d", len(req.Records), maxBatchRecords), http.StatusRequestEntityTooLarge)
		return
	}

	peerNode, hasNodeCert := peerNodeFromTLS(r.TLS)
	if r.TLS != nil && d.cfg.RequireNodeCert && !hasNodeCert {
		http.Error(w, "client certificate must have CN=system:node:<nodeName>", http.StatusForbidden)
		return
	}

	// Authorize every record before mutating the store so partial batches cannot
	// bypass authorization checks.
	for _, rec := range req.Records {
		if hasNodeCert && rec.OwnerNode != peerNode {
			http.Error(w, fmt.Sprintf("node %q cannot put record owned by %q", peerNode, rec.OwnerNode), http.StatusForbidden)
			return
		}
	}

	now := d.cfg.Now()
	var maxSeq map[string]uint64
	for _, rec := range req.Records {
		accepted, existingSeq, err := d.store.Put(rec, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if accepted {
			// Keep this node's reader cache coherent when it also stores the key.
			d.cache.Delete(rec.IP)
		} else if existingSeq > 0 {
			if maxSeq == nil {
				maxSeq = make(map[string]uint64)
			}
			maxSeq[rec.IP] = existingSeq
		}
	}

	dhtStoreRecords.Set(float64(d.store.Len()))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(putResponse{MaxSeq: maxSeq})
}

func (d *DHT) handleGet(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip query parameter is required", http.StatusBadRequest)
		return
	}
	recs := d.store.Get(ip, d.cfg.Now())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(getResponse{Records: recs})
}

func peerNodeFromTLS(state *tls.ConnectionState) (string, bool) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", false
	}
	cn := state.VerifiedChains[0][0].Subject.CommonName
	nodeName, ok := strings.CutPrefix(cn, "system:node:")
	if !ok || nodeName == "" {
		return "", false
	}
	return nodeName, true
}
