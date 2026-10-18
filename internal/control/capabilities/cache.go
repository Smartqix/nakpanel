package capabilities

import (
	"context"
	"errors"
	"log"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
	"golang.org/x/sync/singleflight"
)

type Reader interface {
	RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error)
}

type Option func(*Cache)

func WithTTL(ttl time.Duration) Option {
	return func(c *Cache) { c.ttl = ttl }
}

func WithProbeTimeout(timeout time.Duration) Option {
	return func(c *Cache) { c.timeout = timeout }
}

// Cache keeps display reads fast. Runtime operations must use the live reader.
type Cache struct {
	reader  Reader
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time
	group   singleflight.Group

	mu         sync.Mutex
	value      types.RuntimeCapabilities
	hasValue   bool
	expiresAt  time.Time
	retryAfter time.Time
	lastErr    error
	generation uint64
}

func New(reader Reader, options ...Option) *Cache {
	c := &Cache{reader: reader, ttl: 5 * time.Minute, timeout: 20 * time.Second, now: time.Now}
	for _, option := range options {
		option(c)
	}
	return c
}

var errInvalidated = errors.New("capability cache invalidated")

func (c *Cache) RuntimeCapabilities(ctx context.Context) (types.RuntimeCapabilities, error) {
	for {
		if err := ctx.Err(); err != nil {
			return types.RuntimeCapabilities{}, err
		}
		c.mu.Lock()
		now := c.now()
		value, hasValue := c.value, c.hasValue
		if (hasValue && now.Before(c.expiresAt)) || now.Before(c.retryAfter) {
			err := c.lastErr
			c.mu.Unlock()
			if hasValue {
				return clone(value), nil
			}
			return types.RuntimeCapabilities{}, err
		}
		generation := c.generation
		result := c.group.DoChan(strconv.FormatUint(generation, 10), func() (any, error) {
			return c.refresh(ctx, generation)
		})
		c.mu.Unlock()
		if hasValue {
			return clone(value), nil
		}
		select {
		case <-ctx.Done():
			return types.RuntimeCapabilities{}, ctx.Err()
		case result := <-result:
			if err := ctx.Err(); err != nil {
				return types.RuntimeCapabilities{}, err
			}
			if errors.Is(result.Err, errInvalidated) {
				continue
			}
			if result.Err != nil {
				return types.RuntimeCapabilities{}, result.Err
			}
			return clone(result.Val.(types.RuntimeCapabilities)), nil
		}
	}
}

func (c *Cache) refresh(ctx context.Context, generation uint64) (types.RuntimeCapabilities, error) {
	c.mu.Lock()
	if generation != c.generation {
		c.mu.Unlock()
		return types.RuntimeCapabilities{}, errInvalidated
	}
	// A caller may have observed a miss just before the previous flight finished.
	if (c.hasValue && c.now().Before(c.expiresAt)) || c.now().Before(c.retryAfter) {
		value, err := c.value, c.lastErr
		if c.hasValue {
			err = nil
		}
		c.mu.Unlock()
		return value, err
	}
	c.mu.Unlock()

	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	value, err := c.reader.RuntimeCapabilities(probeCtx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != c.generation {
		return types.RuntimeCapabilities{}, errInvalidated
	}
	if err != nil {
		c.lastErr = err
		c.retryAfter = c.now().Add(15 * time.Second)
		if c.hasValue {
			log.Printf("capabilities: refresh failed; using previous value: %v", err)
			return c.value, nil
		}
		return types.RuntimeCapabilities{}, err
	}
	c.value = clone(value)
	c.hasValue = true
	c.expiresAt = c.now().Add(c.ttl)
	c.lastErr = nil
	c.retryAfter = time.Time{}
	return c.value, nil
}

func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	c.value = types.RuntimeCapabilities{}
	c.hasValue = false
	c.expiresAt = time.Time{}
	c.retryAfter = time.Time{}
	c.lastErr = nil
}

func clone(value types.RuntimeCapabilities) types.RuntimeCapabilities {
	value.PHPVersions = slices.Clone(value.PHPVersions)
	value.ApplicationHealth = slices.Clone(value.ApplicationHealth)
	value.PHPRuntimes = slices.Clone(value.PHPRuntimes)
	for i := range value.PHPRuntimes {
		runtime := &value.PHPRuntimes[i]
		runtime.Extensions = slices.Clone(runtime.Extensions)
		runtime.MissingExtensions = slices.Clone(runtime.MissingExtensions)
		runtime.ValidationErrors = slices.Clone(runtime.ValidationErrors)
	}
	return value
}
