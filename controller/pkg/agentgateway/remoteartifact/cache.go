package remoteartifact

import (
	"errors"
	"sync"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type Cache[E any] struct {
	mu      sync.Mutex
	entries map[remotehttp.FetchKey]E
	key     func(E) remotehttp.FetchKey
}

func NewCache[E any](key func(E) remotehttp.FetchKey) *Cache[E] {
	return &Cache[E]{
		entries: make(map[remotehttp.FetchKey]E),
		key:     key,
	}
}

func (c *Cache[E]) Load(stored []E, validate func(E) error) error {
	newEntries := make(map[remotehttp.FetchKey]E, len(stored))
	errs := make([]error, 0)

	for _, entry := range stored {
		if validate != nil {
			if err := validate(entry); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		newEntries[c.key(entry)] = entry
	}

	c.mu.Lock()
	c.entries = newEntries
	c.mu.Unlock()
	return errors.Join(errs...)
}

func (c *Cache[E]) Get(requestKey remotehttp.FetchKey) (E, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[requestKey]
	return entry, ok
}

func (c *Cache[E]) Put(entry E) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[c.key(entry)] = entry
}

func (c *Cache[E]) Delete(requestKey remotehttp.FetchKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, existed := c.entries[requestKey]
	delete(c.entries, requestKey)
	return existed
}

func (c *Cache[E]) Keys() []remotehttp.FetchKey {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys := make([]remotehttp.FetchKey, 0, len(c.entries))
	for key := range c.entries {
		keys = append(keys, key)
	}
	return keys
}
