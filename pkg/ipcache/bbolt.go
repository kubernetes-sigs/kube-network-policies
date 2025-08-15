/*
Copyright 2025 The Kubernetes Authors.

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

package ipcache

import (
	"encoding/binary"
	"errors"
	"time"

	"go.etcd.io/bbolt"
	bbolterrors "go.etcd.io/bbolt/errors"
	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

var (
	// Bucket names
	dataBucketName = []byte("ipcache_data")
	metaBucketName = []byte("ipcache_meta")

	// Metadata keys
	lastRevisionKey  = []byte("lastRevision")
	lastClusterIDKey = []byte("lastClusterID")
	lastMemberIDKey  = []byte("lastMemberID")

	errNotFound = errors.New("not found")
)

// BoltStore implements both the Store and SyncMetadataStore interfaces.
type BoltStore struct {
	db *bbolt.DB
}

var _ Store = &BoltStore{}
var _ SyncMetadataStore = &BoltStore{}
var _ api.PodInfoProvider = &BoltStore{}

// NewBoltStore creates or opens a BoltDB database and ensures the required buckets exist.
func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	// Ensure both data and metadata buckets exist.
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(dataBucketName); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(metaBucketName); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &BoltStore{db: db}, nil
}

// --- Store Interface Implementation ---

func (s *BoltStore) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	var podInfo api.PodInfo
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(dataBucketName)
		val := b.Get([]byte(ip))
		if val == nil {
			return errNotFound
		}
		return proto.Unmarshal(val, &podInfo)
	})

	if err != nil {
		return nil, false
	}
	return &podInfo, true
}

func (s *BoltStore) Upsert(ip string, info *api.PodInfo) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(dataBucketName)
		data, err := proto.Marshal(info)
		if err != nil {
			return err
		}
		return b.Put([]byte(ip), data)
	})
}

func (s *BoltStore) Delete(ip string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(dataBucketName)
		return b.Delete([]byte(ip))
	})
}

func (s *BoltStore) List() ([]*api.PodInfo, error) {
	var infos []*api.PodInfo
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(dataBucketName)
		return b.ForEach(func(k, v []byte) error {
			var podInfo api.PodInfo
			if err := proto.Unmarshal(v, &podInfo); err == nil {
				infos = append(infos, &podInfo)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return infos, nil
}

// Clear atomically deletes and recreates the main data bucket, effectively
// removing all entries.
func (s *BoltStore) Clear() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.DeleteBucket(dataBucketName); err != nil {
			if !errors.Is(err, bbolterrors.ErrBucketNotFound) {
				return err
			}
		}
		_, err := tx.CreateBucket(dataBucketName)
		if err != nil {
			return err
		}
		if err := tx.DeleteBucket(metaBucketName); err != nil {
			if !errors.Is(err, bbolterrors.ErrBucketNotFound) {
				return err
			}
		}
		_, err = tx.CreateBucket(metaBucketName)
		if err != nil {
			return err
		}
		return nil
	})
}

func (s *BoltStore) Close() error {
	return s.db.Close()
}

// --- SyncMetadataStore Interface Implementation ---

func (s *BoltStore) GetSyncMetadata() (*SyncMetadata, error) {
	meta := &SyncMetadata{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(metaBucketName)

		revBytes := b.Get(lastRevisionKey)
		if revBytes != nil {
			meta.Revision = int64(binary.BigEndian.Uint64(revBytes))
		}
		clusterIDBytes := b.Get(lastClusterIDKey)
		if clusterIDBytes != nil {
			meta.ClusterID = binary.BigEndian.Uint64(clusterIDBytes)
		}
		memberIDBytes := b.Get(lastMemberIDKey)
		if memberIDBytes != nil {
			meta.MemberID = binary.BigEndian.Uint64(memberIDBytes)
		}
		return nil
	})
	return meta, err
}

func (s *BoltStore) SetSyncMetadata(meta *SyncMetadata) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(metaBucketName)

		revBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(revBytes, uint64(meta.Revision))
		if err := b.Put(lastRevisionKey, revBytes); err != nil {
			return err
		}

		clusterIDBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(clusterIDBytes, meta.ClusterID)
		if err := b.Put(lastClusterIDKey, clusterIDBytes); err != nil {
			return err
		}

		memberIDBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(memberIDBytes, meta.MemberID)
		return b.Put(lastMemberIDKey, memberIDBytes)
	})
}
