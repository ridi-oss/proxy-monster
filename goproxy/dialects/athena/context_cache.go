package athena

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/tidwall/buntdb"
	"google.golang.org/protobuf/proto"
)

const (
	maxContextBytes    = 64 << 10
	maxContextAOFBytes = 256 << 20
	contextFormatKey   = "format"
	contextFormat      = "athena-enforcement-context-v1"
)

var (
	ErrContextConflict = errors.New("athena: original context association conflicts")
	ErrContextCapacity = errors.New("athena: enforcement context capacity reached")
	ErrContextCorrupt  = errors.New("athena: corrupt or incompatible enforcement context")
)

type EnforcementContextCache struct {
	mu       sync.Mutex
	db       *buntdb.DB
	file     *os.File
	lock     *flock.Flock
	syncFile func() error
	failure  error
	capacity int
	now      func() time.Time
}

func OpenContextCache(path string, capacity int) (*EnforcementContextCache, error) {
	if capacity <= 0 {
		return nil, errors.New("athena: positive context capacity required")
	}
	cache := &EnforcementContextCache{capacity: capacity, now: time.Now}
	created := false
	if path != ":memory:" {
		var err error
		cache.file, cache.lock, created, err = openPrivateAOF(path)
		if err != nil {
			return nil, err
		}
		cache.syncFile = cache.file.Sync
		if !created {
			if err = validateContextAOF(cache.file, capacity); err != nil {
				_ = cache.Close()
				return nil, err
			}
		}
	}
	db, err := buntdb.Open(path)
	if err != nil {
		_ = cache.Close()
		return nil, err
	}
	cache.db = db
	// BuntDB ignores fsync errors; this wrapper checks each sync and keeps the inode stable.
	err = db.SetConfig(buntdb.Config{SyncPolicy: buntdb.Never, AutoShrinkDisabled: true})
	if err == nil && (path == ":memory:" || created) {
		err = db.Update(func(tx *buntdb.Tx) error { _, _, err := tx.Set(contextFormatKey, contextFormat, nil); return err })
		if err == nil {
			err = cache.sync()
		}
	}
	if err != nil {
		_ = cache.Close()
		return nil, err
	}
	return cache, nil
}

func (c *EnforcementContextCache) Lookup(datasource, resourceID, owner string, targetBinding []byte) (*enginepb.AthenaCachedContext, error) {
	record, err := c.Find(datasource, resourceID)
	if err != nil {
		return nil, err
	}
	if record.Owner != owner || !bytes.Equal(record.TargetBinding, targetBinding) {
		return nil, ErrUnauthorized
	}
	return record, nil
}

// Find returns the unexpired context for a resource without an owner check; the control plane decides
// whether the caller owns it.
func (c *EnforcementContextCache) Find(datasource, resourceID string) (*enginepb.AthenaCachedContext, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return nil, c.failure
	}
	if c.db == nil {
		return nil, buntdb.ErrDatabaseClosed
	}
	key, err := contextKey(datasource, resourceID)
	if err != nil {
		return nil, err
	}
	var record *enginepb.AthenaCachedContext
	err = c.db.View(func(tx *buntdb.Tx) error {
		value, err := tx.Get(key)
		if errors.Is(err, buntdb.ErrNotFound) {
			return ErrOriginalContextUnavailable
		}
		if err != nil {
			return err
		}
		record, err = decodeContext([]byte(value))
		return err
	})
	if err != nil {
		return nil, err
	}
	if !record.ExpiresAt.AsTime().After(c.now()) || record.ResourceId != resourceID {
		return nil, ErrOriginalContextUnavailable
	}
	return record, nil
}

func (c *EnforcementContextCache) Associate(datasource string, record *enginepb.AthenaCachedContext) error {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return err
	}
	copy, err := decodeContext(data)
	if err != nil {
		return err
	}
	key, err := contextKey(datasource, copy.ResourceId)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	if c.db == nil {
		return buntdb.ErrDatabaseClosed
	}
	if !copy.ExpiresAt.AsTime().After(c.now()) {
		return ErrOriginalContextUnavailable
	}
	if c.file != nil {
		info, err := c.file.Stat()
		if err != nil {
			return err
		}
		if info.Size()+int64(len(data)+len(key)+128) > maxContextAOFBytes {
			return ErrContextCapacity
		}
	}
	changed := false
	err = c.db.Update(func(tx *buntdb.Tx) error {
		old, err := tx.Get(key)
		if err == nil {
			if old == string(data) {
				return nil
			}
			return ErrContextConflict
		}
		if !errors.Is(err, buntdb.ErrNotFound) {
			return err
		}
		count, err := tx.Len()
		if err != nil {
			return err
		}
		if count-1 >= c.capacity {
			var expired []string
			var scanErr error
			err = tx.Ascend("", func(key, value string) bool {
				if key == contextFormatKey {
					return true
				}
				context, err := decodeContext([]byte(value))
				if err != nil {
					scanErr = err
					return false
				}
				if !context.ExpiresAt.AsTime().After(c.now()) {
					expired = append(expired, key)
				}
				return true
			})
			if err != nil {
				return err
			}
			if scanErr != nil {
				return scanErr
			}
			for _, key := range expired {
				if _, err = tx.Delete(key); err != nil {
					return err
				}
			}
			if count-1-len(expired) >= c.capacity {
				return ErrContextCapacity
			}
		}
		_, _, err = tx.Set(key, string(data), nil)
		changed = err == nil
		return err
	})
	if err != nil {
		return err
	}
	if changed {
		return c.sync()
	}
	return nil
}

// Rebind records the result shape a context was first read under. Only the metadata digest may change,
// only from empty, and only over the exact bytes the caller read; anything else conflicts.
func (c *EnforcementContextCache) Rebind(datasource string, previous, next *enginepb.AthenaCachedContext) error {
	before, err := proto.MarshalOptions{Deterministic: true}.Marshal(previous)
	if err != nil {
		return err
	}
	after, err := proto.MarshalOptions{Deterministic: true}.Marshal(next)
	if err != nil {
		return err
	}
	decoded, err := decodeContext(after)
	if err != nil {
		return err
	}
	unchanged := proto.Clone(decoded).(*enginepb.AthenaCachedContext)
	unchanged.MetadataDigest = previous.GetMetadataDigest()
	if len(previous.GetMetadataDigest()) != 0 || len(decoded.MetadataDigest) != 32 || !proto.Equal(unchanged, previous) {
		return ErrContextConflict
	}
	key, err := contextKey(datasource, decoded.ResourceId)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	if c.db == nil {
		return buntdb.ErrDatabaseClosed
	}
	err = c.db.Update(func(tx *buntdb.Tx) error {
		current, err := tx.Get(key)
		if errors.Is(err, buntdb.ErrNotFound) {
			return ErrOriginalContextUnavailable
		}
		if err != nil {
			return err
		}
		if current == string(after) {
			return nil
		}
		if current != string(before) {
			return ErrContextConflict
		}
		_, _, err = tx.Set(key, string(after), nil)
		return err
	})
	if err != nil {
		return err
	}
	return c.sync()
}

func (c *EnforcementContextCache) sync() error {
	if c.syncFile != nil {
		if err := c.syncFile(); err != nil {
			c.failure = fmt.Errorf("athena: enforcement context sync failed: %w", err)
			return c.failure
		}
	}
	return nil
}

func (c *EnforcementContextCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var failures []error
	if c.db != nil {
		failures = append(failures, c.sync(), c.db.Close())
		c.db = nil
	}
	if c.file != nil {
		failures = append(failures, c.file.Close())
		c.file = nil
	}
	if c.lock != nil {
		failures = append(failures, c.lock.Close())
		c.lock = nil
	}
	return errors.Join(failures...)
}

func contextKey(datasource, resourceID string) (string, error) {
	if datasource == "" || resourceID == "" || len(datasource) > 256 || len(resourceID) > 256 {
		return "", ErrContextCorrupt
	}
	return "context:" + base64.RawURLEncoding.EncodeToString([]byte(datasource)) + ":" + base64.RawURLEncoding.EncodeToString([]byte(resourceID)), nil
}

func decodeContext(data []byte) (*enginepb.AthenaCachedContext, error) {
	if len(data) == 0 || len(data) > maxContextBytes {
		return nil, ErrContextCorrupt
	}
	var record enginepb.AthenaCachedContext
	if err := proto.Unmarshal(data, &record); err != nil {
		return nil, ErrContextCorrupt
	}
	if record.Version != 1 || record.ContextId == "" || record.ResourceId == "" || record.Owner == "" || len(record.TargetBinding) != 32 || record.ExpiresAt == nil || record.ExpiresAt.CheckValid() != nil || len(record.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrContextCorrupt
	}
	if record.ExpectedWidth != nil && *record.ExpectedWidth > 1<<20 {
		return nil, ErrContextCorrupt
	}
	if len(record.MetadataDigest) != 0 && len(record.MetadataDigest) != 32 {
		return nil, ErrContextCorrupt
	}
	if len(record.RequestBinding) != 0 && len(record.RequestBinding) != 32 {
		return nil, ErrContextCorrupt
	}
	var verdict pb.Verdict
	if len(record.EnforcementInstructions) == 0 || proto.Unmarshal(record.EnforcementInstructions, &verdict) != nil {
		return nil, ErrContextCorrupt
	}
	if verdict.Decision != pb.EnfAction_ALLOW && verdict.Decision != pb.EnfAction_MASK {
		return nil, ErrContextCorrupt
	}
	trimmed := &pb.Verdict{Decision: verdict.Decision, Masks: verdict.Masks, UnmaskablePermitted: verdict.UnmaskablePermitted, SanitizeDiagnostics: verdict.SanitizeDiagnostics, DecisionId: verdict.DecisionId}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(trimmed)
	if err != nil || !proto.Equal(&verdict, trimmed) || !bytes.Equal(canonical, record.EnforcementInstructions) || len(record.ExpiresAt.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrContextCorrupt
	}
	for _, mask := range verdict.Masks {
		if mask == nil || mask.Ordinal == nil || *mask.Ordinal < 0 || len(mask.ProtoReflect().GetUnknown()) != 0 {
			return nil, ErrContextCorrupt
		}
		if record.ExpectedWidth != nil && uint32(*mask.Ordinal) >= *record.ExpectedWidth {
			return nil, ErrContextCorrupt
		}
	}
	if verdict.Decision == pb.EnfAction_ALLOW && len(verdict.Masks) > 0 {
		return nil, ErrContextCorrupt
	}
	return &record, nil
}

func openPrivateAOF(path string) (*os.File, *flock.Flock, bool, error) {
	if !filepath.IsAbs(path) {
		return nil, nil, false, errors.New("athena: context path must be absolute")
	}
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if err != nil {
		return nil, nil, false, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, false, errors.New("athena: context directory must be private")
	}
	lockPath := path + ".lock"
	for _, candidate := range []string{path, lockPath} {
		info, err := os.Lstat(candidate)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, false, err
		}
		if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
			return nil, nil, false, errors.New("athena: context files must be private regular files")
		}
	}
	lock := flock.New(lockPath, flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		_ = lock.Close()
		return nil, nil, false, errors.New("athena: context file is already owned")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = os.OpenFile(path, os.O_RDWR, 0600)
	}
	if err != nil {
		_ = lock.Close()
		return nil, nil, false, err
	}
	if created {
		dir, err := os.Open(directory)
		if err == nil {
			err = dir.Sync()
			_ = dir.Close()
		}
		if err != nil {
			_ = file.Close()
			_ = lock.Close()
			return nil, nil, false, err
		}
	}
	return file, lock, created, nil
}

func validContextKey(key string) bool {
	parts := strings.Split(key, ":")
	if len(parts) != 3 || parts[0] != "context" {
		return false
	}
	for _, part := range parts[1:] {
		value, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || len(value) == 0 || len(value) > 256 {
			return false
		}
	}
	return true
}
