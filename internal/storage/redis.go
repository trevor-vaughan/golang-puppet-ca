// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package storage

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig configures the Redis/Valkey-backed storage backend. Either
// Addrs or SentinelMasterName+SentinelAddrs must be set.
type RedisConfig struct {
	// Addrs is the list of Redis/Valkey instance addresses (host:port). In
	// direct mode the first address is used. Ignored when SentinelMasterName
	// is non-empty.
	Addrs []string

	// SentinelMasterName, if non-empty, switches the backend to Sentinel
	// mode: the client asks SentinelAddrs for the current primary and
	// follows failovers automatically.
	SentinelMasterName string
	// SentinelAddrs is the list of Sentinel addresses (host:port). Only
	// consulted when SentinelMasterName is set.
	SentinelAddrs []string
	// SentinelUsername / SentinelPassword authenticate to the Sentinels
	// themselves (distinct from the primary's auth, which uses Username /
	// Password).
	SentinelUsername string
	SentinelPassword string

	// DB selects the numeric logical database. Zero is fine for most
	// deployments and required for Redis Cluster-like routing.
	DB int
	// Username / Password authenticate to the Redis primary.
	Username string
	Password string
	// TLS, if non-nil, configures TLS for the connection.
	TLS *tls.Config

	// DialTimeout bounds the initial connection attempt. Zero uses 5s.
	DialTimeout time.Duration
	// RequestTimeout bounds per-request operations. Zero uses 5s.
	RequestTimeout time.Duration

	// KeyPrefix namespaces all keys. Defaults to "puppet-ca" when empty.
	// Redis convention uses ":" as a separator.
	KeyPrefix string

	// LockTTL is the time-to-live on acquired distributed locks. If the
	// holder process dies without Unlock, the lock releases automatically
	// after this interval. Zero uses 30s.
	LockTTL time.Duration
}

const (
	redisDefaultTimeout = 5 * time.Second
	redisDefaultPrefix  = "puppet-ca"
	redisDefaultLockTTL = 30 * time.Second
	redisHeartbeatDenom = 3 // heartbeat every LockTTL / redisHeartbeatDenom
	redisLockTokenBytes = 16
)

func (c *RedisConfig) applyDefaults() {
	if c.DialTimeout == 0 {
		c.DialTimeout = redisDefaultTimeout
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = redisDefaultTimeout
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = redisDefaultPrefix
	}
	c.KeyPrefix = strings.TrimRight(c.KeyPrefix, ":")
	if c.LockTTL == 0 {
		c.LockTTL = redisDefaultLockTTL
	}
}

// RedisBackend is a Backend implementation backed by a Redis- (or Valkey-)
// compatible server. Optionally uses Redis Sentinel for automatic failover.
//
// Blob contents are wrapped with an 8-byte big-endian nanosecond mtime prefix
// (same encoding as the etcd backend) so ModTime answers from the same
// round-trip as Get. AppendLine is performed server-side via a Lua script so
// concurrent appenders on different replicas do not lose lines. Distributed
// locks use SET NX PX with a per-acquisition token, a background heartbeat
// while the lock is held, and a token-matching Lua script on Unlock; this is
// sufficient for a single logical Redis/Sentinel-primary, which is the
// deployment this backend targets.
type RedisBackend struct {
	client  redis.UniversalClient
	owned   bool // true when Close should close the client
	prefix  string
	timeout time.Duration
	lockTTL time.Duration

	appendScript *redis.Script
	renewScript  *redis.Script
	unlockScript *redis.Script

	appendMu sync.Mutex // serialises AppendLine within this process

	// localLocks holds a *sync.Mutex per lock name. Redis's SET NX is not
	// re-entrant from the same client, and even if it were, multiple
	// goroutines inside this process would all present the same token and
	// race each other. Serialising intra-process contention locally first
	// is the same pattern the etcd backend uses.
	localLocks sync.Map
}

// redisLayout maps logical keys to their physical Redis sub-keys. CSR and
// signed-cert keys are handled in physicalKey.
var redisLayout = map[string]string{
	KeyCACert:        "ca:cert",
	KeyCAPubKey:      "ca:pubkey",
	KeyCAKey:         "ca:key",
	KeyCRL:           "ca:crl",
	KeySerial:        "serial",
	KeyInventory:     "inventory:data",
	KeyInventoryHMAC: "inventory:hmac",
	KeyHMACKey:       "private:hmac_key",

	KeyServingCert:       "serving:cert",
	KeyServingKey:        "private:serving_key",
	KeyServingSuperseded: "serving:superseded",
}

// appendLuaScript atomically appends data to an existing blob, preserving
// the 8-byte mtime prefix layout. KEYS[1] is the full physical key; ARGV[1]
// is the 8-byte big-endian nanosecond mtime to write; ARGV[2] is the line
// bytes to append. If the key does not exist, a fresh blob is created
// containing just the new mtime and the appended line.
const appendLuaScript = `
local v = redis.call('GET', KEYS[1])
local body
if v then
  body = string.sub(v, 9)
else
  body = ''
end
redis.call('SET', KEYS[1], ARGV[1] .. body .. ARGV[2])
return 1
`

// renewLuaScript extends the TTL on a held lock iff the current value matches
// the holder's token. KEYS[1] is the lock key, ARGV[1] is the token, ARGV[2]
// is the new TTL in milliseconds. Returns 1 on success, 0 otherwise.
const renewLuaScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
else
  return 0
end
`

// unlockLuaScript releases a lock iff the current value matches the holder's
// token. KEYS[1] is the lock key, ARGV[1] is the token. Returns 1 on
// successful delete, 0 otherwise (lock expired or taken by someone else).
const unlockLuaScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
else
  return 0
end
`

// NewRedisBackend connects to a Redis/Valkey instance (or the primary behind
// a set of Sentinels) and returns a ready backend. The caller must call
// Close to release the underlying client.
func NewRedisBackend(cfg RedisConfig) (*RedisBackend, error) {
	cfg.applyDefaults()

	if cfg.SentinelMasterName == "" && len(cfg.Addrs) == 0 {
		return nil, fmt.Errorf("redis backend requires Addrs or SentinelMasterName+SentinelAddrs")
	}
	if cfg.SentinelMasterName != "" && len(cfg.SentinelAddrs) == 0 {
		return nil, fmt.Errorf("redis backend: SentinelMasterName requires SentinelAddrs")
	}

	var client redis.UniversalClient
	if cfg.SentinelMasterName != "" {
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       cfg.SentinelMasterName,
			SentinelAddrs:    cfg.SentinelAddrs,
			SentinelUsername: cfg.SentinelUsername,
			SentinelPassword: cfg.SentinelPassword,
			DB:               cfg.DB,
			Username:         cfg.Username,
			Password:         cfg.Password,
			TLSConfig:        cfg.TLS,
			DialTimeout:      cfg.DialTimeout,
			ReadTimeout:      cfg.RequestTimeout,
			WriteTimeout:     cfg.RequestTimeout,
		})
	} else {
		client = redis.NewClient(&redis.Options{
			Addr:         cfg.Addrs[0],
			DB:           cfg.DB,
			Username:     cfg.Username,
			Password:     cfg.Password,
			TLSConfig:    cfg.TLS,
			DialTimeout:  cfg.DialTimeout,
			ReadTimeout:  cfg.RequestTimeout,
			WriteTimeout: cfg.RequestTimeout,
		})
	}

	return newRedisBackendFromClient(client, true, cfg.KeyPrefix, cfg.RequestTimeout, cfg.LockTTL), nil
}

// NewRedisBackendFromClient wraps an existing redis.UniversalClient. The
// backend does not take ownership and Close leaves the client open. Used by
// tests that need to share a single miniredis across backends.
func NewRedisBackendFromClient(client redis.UniversalClient, keyPrefix string, requestTimeout, lockTTL time.Duration) *RedisBackend {
	cfg := RedisConfig{KeyPrefix: keyPrefix, RequestTimeout: requestTimeout, LockTTL: lockTTL}
	cfg.applyDefaults()
	return newRedisBackendFromClient(client, false, cfg.KeyPrefix, cfg.RequestTimeout, cfg.LockTTL)
}

func newRedisBackendFromClient(client redis.UniversalClient, owned bool, prefix string, timeout, lockTTL time.Duration) *RedisBackend {
	return &RedisBackend{
		client:       client,
		owned:        owned,
		prefix:       prefix,
		timeout:      timeout,
		lockTTL:      lockTTL,
		appendScript: redis.NewScript(appendLuaScript),
		renewScript:  redis.NewScript(renewLuaScript),
		unlockScript: redis.NewScript(unlockLuaScript),
	}
}

// physicalKey translates a logical key into its Redis key. Returns an error
// for unknown logical keys or obviously unsafe components (e.g. "..").
func (b *RedisBackend) physicalKey(logical string) (string, error) {
	if err := validateKey(logical); err != nil {
		return "", err
	}
	if sub, ok := redisLayout[logical]; ok {
		return b.prefix + ":" + sub, nil
	}
	switch {
	case strings.HasPrefix(logical, csrPrefix):
		subj := strings.TrimPrefix(logical, csrPrefix)
		return b.prefix + ":requests:" + subj, nil
	case strings.HasPrefix(logical, certPrefix):
		subj := strings.TrimPrefix(logical, certPrefix)
		return b.prefix + ":signed:" + subj, nil
	}
	return "", fmt.Errorf("unknown key %q", logical)
}

// callCtx layers the backend's per-call timeout on top of the caller's
// context. Caller cancellation always wins; if the caller has no deadline
// b.timeout becomes the effective bound.
func (b *RedisBackend) callCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, b.timeout)
}

// EnsureReady verifies connectivity with a PING. Redis has no directory
// concept so there is nothing else to prepare.
func (b *RedisBackend) EnsureReady(ctx context.Context) error {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	if err := b.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis not reachable: %w", err)
	}
	return nil
}

// Get returns the (unwrapped) blob at key, wrapping fs.ErrNotExist when absent.
func (b *RedisBackend) Get(ctx context.Context, key string) ([]byte, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return nil, err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	raw, err := b.client.Get(ctx, phys).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	_, data, err := decodeBlob(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding blob %q: %w", key, err)
	}
	return data, nil
}

// Put writes the blob at key. The BlobKind hint is recorded but has no
// effect on the stored form: Redis access control is managed server-side.
func (b *RedisBackend) Put(ctx context.Context, key string, data []byte, _ BlobKind) error {
	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	return b.client.Set(ctx, phys, encodeBlob(time.Now(), data), 0).Err()
}

// Delete removes key, wrapping fs.ErrNotExist when the key is absent.
func (b *RedisBackend) Delete(ctx context.Context, key string) error {
	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	n, err := b.client.Del(ctx, phys).Result()
	if err != nil {
		return err
	}
	if n == 0 {
		return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrNotExist}
	}
	return nil
}

// Exists reports whether key is present.
func (b *RedisBackend) Exists(ctx context.Context, key string) (bool, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return false, err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	n, err := b.client.Exists(ctx, phys).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// List returns the logical keys sharing prefix. Only csrPrefix and certPrefix
// are supported. Uses SCAN under the hood to avoid blocking the server.
func (b *RedisBackend) List(ctx context.Context, prefix string) ([]string, error) {
	var subDir, outPrefix string
	switch prefix {
	case csrPrefix:
		subDir = "requests:"
		outPrefix = csrPrefix
	case certPrefix:
		subDir = "signed:"
		outPrefix = certPrefix
	default:
		return nil, fmt.Errorf("unsupported list prefix %q", prefix)
	}
	physPrefix := b.prefix + ":" + subDir
	match := physPrefix + "*"

	var (
		out    []string
		cursor uint64
	)
	// Each SCAN page gets its own deadline. With a single ctx spanning
	// the whole loop, a large keyspace on a slow link could expire the
	// shared deadline mid-walk and silently truncate the listing; the
	// per-page form bounds each network round-trip independently.
	for {
		keys, next, err := func() ([]string, uint64, error) {
			pageCtx, cancel := b.callCtx(ctx)
			defer cancel()
			return b.client.Scan(pageCtx, cursor, match, 100).Result()
		}()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			name := strings.TrimPrefix(k, physPrefix)
			// Skip accidentally-nested keys.
			if strings.Contains(name, ":") {
				continue
			}
			out = append(out, outPrefix+name)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return out, nil
}

// AppendLine atomically appends data to key. Concurrent appends from this
// process are serialised on appendMu; concurrent appends from other
// processes are resolved by a server-side Lua script that reads the current
// blob, appends, and writes back in a single atomic step.
func (b *RedisBackend) AppendLine(ctx context.Context, key string, data []byte, _ BlobKind) error {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}

	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	mtime := encodeMtime(time.Now())
	_, err = b.appendScript.Run(ctx, b.client, []string{phys}, mtime, data).Result()
	return err
}

// ModTime returns the wall-clock timestamp recorded when the blob was last
// written. Returns fs.ErrNotExist-wrapped when the key is absent.
func (b *RedisBackend) ModTime(ctx context.Context, key string) (time.Time, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return time.Time{}, err
	}
	rangeCtx, cancel := b.callCtx(ctx)
	defer cancel()
	// Only the first 8 bytes encode the mtime; GETRANGE avoids pulling the
	// whole blob.
	raw, err := b.client.GetRange(rangeCtx, phys, 0, 7).Bytes()
	if err != nil {
		return time.Time{}, err
	}
	if len(raw) == 0 {
		// GETRANGE on a missing key returns an empty string — same as a
		// present-but-empty key. Distinguish with a cheap Exists.
		ok, existsErr := b.Exists(ctx, key)
		if existsErr != nil {
			return time.Time{}, existsErr
		}
		if !ok {
			return time.Time{}, &fs.PathError{Op: "modtime", Path: key, Err: fs.ErrNotExist}
		}
		return time.Time{}, fmt.Errorf("blob %q: empty", key)
	}
	mtime, _, err := decodeBlob(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("decoding blob %q: %w", key, err)
	}
	return mtime, nil
}

// AcquireLock obtains a distributed mutex under <prefix>:locks:<name> using
// SET NX PX with a per-acquisition token. Local goroutines racing on the
// same name are serialised by a per-name process-local mutex first, then
// the distributed lock is taken so only one process in the cluster holds
// the lock at a time. A heartbeat goroutine extends the TTL while the lock
// is held; Unlock stops it and deletes the lock if we still own it.
//
// NB: Redis replication under Sentinel is asynchronous, so an in-flight
// failover can theoretically release a lock we still believe we hold.
// For `openvox-ca`'s workloads (CRL rotation, bootstrap, per-subject CSR
// serialisation) this narrow window is acceptable; operators needing
// stricter guarantees should prefer the etcd backend.
func (b *RedisBackend) AcquireLock(ctx context.Context, name string) (Unlocker, error) {
	local := b.localLockFor(name)
	local.Lock()

	lockKey := b.prefix + ":locks:" + name
	token, err := newLockToken()
	if err != nil {
		local.Unlock()
		return nil, fmt.Errorf("generating lock token: %w", err)
	}

	// Block until we can acquire or ctx expires. SET NX returns false when
	// the key already exists, so we retry with a short backoff. A single
	// Timer is reused across iterations rather than allocating a fresh
	// time.After channel each retry: under sustained contention the
	// per-iteration form put pressure on the runtime timer heap (and
	// pre-Go-1.23, kept the timer alive until it fired).
	backoff := 50 * time.Millisecond
	const maxBackoff = 500 * time.Millisecond
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	for {
		ok, setErr := b.client.SetNX(ctx, lockKey, token, b.lockTTL).Result()
		if setErr != nil {
			local.Unlock()
			return nil, fmt.Errorf("acquiring redis lock %q: %w", name, setErr)
		}
		if ok {
			break
		}
		select {
		case <-ctx.Done():
			local.Unlock()
			return nil, fmt.Errorf("acquiring redis lock %q: %w", name, ctx.Err())
		case <-timer.C:
		}
		backoff = min(backoff*2, maxBackoff)
		timer.Reset(backoff)
	}

	ul := &redisUnlocker{
		backend:       b,
		lockKey:       lockKey,
		token:         token,
		local:         local,
		stopHeartbeat: make(chan struct{}),
	}
	go ul.heartbeat() //nolint:gosec // G118: lock heartbeat must outlive the request ctx; it owns its own stopHeartbeat lifecycle
	return ul, nil
}

// localLockFor returns the process-local mutex for lock name, creating it
// on first use. Mutexes are never removed; the namespace is small and bounded.
func (b *RedisBackend) localLockFor(name string) *sync.Mutex {
	if v, ok := b.localLocks.Load(name); ok {
		return v.(*sync.Mutex)
	}
	v, _ := b.localLocks.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// redisUnlocker wraps the Redis lock (identified by lockKey+token) plus the
// process-local mutex acquired in AcquireLock. The local mutex is always
// released, even if the distributed unlock fails, so a transient Redis
// error cannot wedge subsequent in-process callers.
type redisUnlocker struct {
	backend       *RedisBackend
	lockKey       string
	token         string
	local         *sync.Mutex
	stopHeartbeat chan struct{}
	heartbeatOnce sync.Once
}

// heartbeat periodically extends the lock TTL so long-running critical
// sections don't expire mid-flight. Runs until Unlock closes stopHeartbeat.
func (u *redisUnlocker) heartbeat() {
	interval := u.backend.lockTTL / redisHeartbeatDenom
	if interval <= 0 {
		interval = time.Second
	}
	ttlMs := int64(u.backend.lockTTL / time.Millisecond)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-u.stopHeartbeat:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), u.backend.timeout)
			res, err := u.backend.renewScript.Run(ctx, u.backend.client, []string{u.lockKey}, u.token, ttlMs).Result()
			cancel()
			if err != nil {
				slog.Warn("Redis lock heartbeat failed", "name", u.lockKey, "error", err)
				continue
			}
			// Renew script returns 0 when the lock is no longer ours
			// (expired, or taken by a different holder after failover).
			// There's nothing useful to do here except log; the Unlock
			// will observe the same mismatch.
			if n, ok := res.(int64); ok && n == 0 {
				slog.Warn("Redis lock is no longer held by this replica", "name", u.lockKey)
			}
		}
	}
}

func (u *redisUnlocker) Unlock() error {
	u.heartbeatOnce.Do(func() { close(u.stopHeartbeat) })
	ctx, cancel := context.WithTimeout(context.Background(), u.backend.timeout)
	defer cancel()
	_, err := u.backend.unlockScript.Run(ctx, u.backend.client, []string{u.lockKey}, u.token).Result()
	u.local.Unlock()
	return err
}

// Close releases the underlying Redis client when owned by this backend.
func (b *RedisBackend) Close() error {
	if !b.owned || b.client == nil {
		return nil
	}
	return b.client.Close()
}

// encodeMtime returns the 8-byte big-endian nanosecond timestamp used as the
// blob mtime prefix. Matches the layout produced by encodeBlob.
func encodeMtime(t time.Time) []byte {
	b := make([]byte, 8)
	// Reuse encodeBlob's layout without allocating a payload.
	wrapped := encodeBlob(t, nil)
	copy(b, wrapped[:8])
	return b
}

// newLockToken returns a hex-encoded random token used to identify a lock
// holder. 16 random bytes is enough to collide less often than the universe
// will exist.
func newLockToken() (string, error) {
	buf := make([]byte, redisLockTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
