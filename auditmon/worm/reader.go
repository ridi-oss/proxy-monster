package worm

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

type Reader struct {
	store       ObjectStore
	anchors     objectCache[Anchor]
	acceptances objectCache[Acceptance]
}

func NewReader(os ObjectStore) *Reader {
	return &Reader{store: os}
}

func (r *Reader) Anchors() ([]Anchor, error) {
	isCheckpoint := func(key string) bool {
		_, ok := parseCheckpointID(key)
		return ok
	}
	anchors, err := r.anchors.read(r.store, checkpointPrefix, isCheckpoint)
	if err != nil {
		return nil, err
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].UpToID < anchors[j].UpToID })
	return anchors, nil
}

func (r *Reader) Acceptances() ([]Acceptance, error) {
	isJSON := func(key string) bool { return strings.HasSuffix(key, ".json") }
	out, err := r.acceptances.read(r.store, acceptancePrefix, isJSON)
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DivergentID < out[j].DivergentID })
	return out, nil
}

type cachedObject[T any] struct {
	version string
	value   T
	parsed  bool
}

type objectCache[T any] struct {
	mu   sync.Mutex
	seen map[string]cachedObject[T]
}

func (c *objectCache[T]) read(os ObjectStore, prefix string, want func(string) bool) ([]T, error) {
	objects, err := os.ListObjects(prefix)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[string]cachedObject[T], len(objects))
	var out []T
	for _, o := range objects {
		if !want(o.Key) {
			continue
		}
		obj, hit := c.seen[o.Key]
		if !hit || obj.version != o.Version {
			body, err := os.Get(o.Key)
			if err != nil {
				return nil, err
			}
			obj = cachedObject[T]{version: o.Version}
			obj.parsed = json.Unmarshal(body, &obj.value) == nil
		}
		next[o.Key] = obj
		if obj.parsed {
			out = append(out, obj.value)
		}
	}
	c.seen = next
	return out, nil
}
