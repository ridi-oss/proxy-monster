package worm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// memoryStore is an in-memory ObjectStore for tests.
type memoryStore struct {
	mu      sync.Mutex
	objects map[string]memoryObject
	puts    uint64
}

type memoryObject struct {
	body    []byte
	version uint64
}

// NewMemory returns an in-memory ObjectStore.
func NewMemory() ObjectStore {
	return &memoryStore{objects: make(map[string]memoryObject)}
}

func (m *memoryStore) Put(key string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := make([]byte, len(body))
	copy(stored, body)
	m.puts++
	m.objects[key] = memoryObject{body: stored, version: m.puts}
	return nil
}

func (m *memoryStore) List(prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (m *memoryStore) ListObjects(prefix string) ([]ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ObjectInfo
	for k, o := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, ObjectInfo{Key: k, Version: strconv.FormatUint(o.version, 10)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (m *memoryStore) Get(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	obj, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("worm: object %q: %w", key, ErrNotFound)
	}
	out := make([]byte, len(obj.body))
	copy(out, obj.body)
	return out, nil
}
