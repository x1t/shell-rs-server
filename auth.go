package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// The key derivation every client runs on the password. A change here is a
// change to the protocol: devices and accounts must agree on it.
const (
	kdfTime    = 3
	kdfMemory  = 64 * 1024
	kdfThreads = 4
	saltSize   = 16
)

// kdfParams is what /api/prelogin tells a client to run.
type kdfParams struct {
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

func paramsFor(salt []byte) kdfParams {
	return kdfParams{Salt: salt, Time: kdfTime, Memory: kdfMemory, Threads: kdfThreads}
}

// authKey is the half of the password's derived key that is sent to log in.
// The other half seals the vault key and never leaves the device.
func authKey(password string, salt []byte) []byte {
	derived := argon2.IDKey([]byte(password), salt, kdfTime, kdfMemory, kdfThreads, 64)
	return derived[32:]
}

// The auth key is the output of a slow KDF, so one hash is enough to keep
// it from being replayed out of a stolen database.
func authHash(authKey []byte) []byte {
	sum := sha256.Sum256(authKey)
	return sum[:]
}

func authMatches(stored, authKey []byte) bool {
	return subtle.ConstantTimeCompare(stored, authHash(authKey)) == 1
}

// fakeSalt answers prelogin for a name that has no account the same way
// every time, so the answer does not tell who has one.
func fakeSalt(secret []byte, username string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(username))
	return mac.Sum(nil)[:saltSize]
}

func newToken() (string, []byte) {
	token := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	return token, tokenHash(token)
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// limiter turns away a client after too many failed logins in a window.
type limiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
	now      func() time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, failures: map[string][]time.Time{}, now: time.Now}
}

func (l *limiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < l.max
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.recent(key), l.now())
}

func (l *limiter) recent(key string) []time.Time {
	cutoff := l.now().Add(-l.window)
	kept := l.failures[key][:0]
	for _, at := range l.failures[key] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}
