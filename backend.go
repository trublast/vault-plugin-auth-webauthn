package webauthnbackend

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	userIDIndexPrefix = "user_id/"
)

// Linker-provided project/build information.
var projectVersion string

// backend implements logical.Backend for WebAuthn authentication.
type backend struct {
	*framework.Backend

	// mu guards the cached config and the derived WebAuthn instance only.
	mu           sync.RWMutex
	cachedConfig *webauthnConfig
	webAuthn     *webauthn.WebAuthn

	// userLocks provides per-user serialization so that concurrent
	// read-modify-write operations on the same StoredUser object cannot
	// corrupt it (e.g. losing a credential), while operations on different
	// users run in parallel.
	userLocks []*locksutil.LockEntry

	// loginSessions and registrationSessions hold in-progress (begin/finish)
	// WebAuthn ceremonies in memory instead of Vault storage. See sessions.go
	// for the rationale (performance-replication friendliness).
	loginSessions        *lru.LRU[string, loginSessionEntry]
	registrationSessions *lru.LRU[string, registrationSessionEntry]
}

// userLock returns the lock guarding the StoredUser identified by name.
func (b *backend) userLock(name string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.userLocks, name)
}

// Factory returns a new logical.Backend.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend {
	b := &backend{
		userLocks:            locksutil.CreateLocks(),
		loginSessions:        newSessionCache[loginSessionEntry](),
		registrationSessions: newSessionCache[registrationSessionEntry](),
	}
	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		Invalidate:  b.invalidate,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login/begin",
				"login/finish",
				"register/begin",
				"register/finish",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathUserList(b),
				pathUser(b),
				pathUserGenerateCode(b),
				pathUserPolicies(b),
				pathUserCredential(b),
				pathRegisterBegin(b),
				pathRegisterFinish(b),
				pathLoginBegin(b),
				pathLoginFinish(b),
			},
		),
		Help:           strings.TrimSpace(backendHelp),
		RunningVersion: projectVersion,
	}
	return b
}

func (b *backend) invalidate(ctx context.Context, key string) {
	if key == configPath {
		b.invalidateConfig()
	}
}

func (b *backend) invalidateConfig() {
	b.mu.Lock()
	b.cachedConfig = nil
	b.webAuthn = nil
	b.mu.Unlock()
}

func (b *backend) config(ctx context.Context, s logical.Storage) (*webauthnConfig, error) {
	b.mu.RLock()
	if b.cachedConfig != nil {
		cfg := b.cachedConfig
		b.mu.RUnlock()
		return cfg, nil
	}
	b.mu.RUnlock()

	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var cfg webauthnConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.cachedConfig = &cfg
	b.mu.Unlock()
	return &cfg, nil
}

// getWebAuthn returns a WebAuthn instance built from the stored config. Caller must have validated config exists.
func (b *backend) getWebAuthn(ctx context.Context, s logical.Storage) (*webauthn.WebAuthn, error) {
	b.mu.RLock()
	if b.webAuthn != nil {
		w := b.webAuthn
		b.mu.RUnlock()
		return w, nil
	}
	b.mu.RUnlock()

	cfg, err := b.config(ctx, s)
	if err != nil || cfg == nil {
		return nil, err
	}

	libConfig := &webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			// Enforce makes the library stamp SessionData.Expires and reject
			// expired sessions server-side at finish (not just rely on the
			// browser). It also gives the tidy a real expiry to act on.
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    sessionTTL,
				TimeoutUVD: sessionTTL,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    sessionTTL,
				TimeoutUVD: sessionTTL,
			},
		},
	}
	w, err := webauthn.New(libConfig)
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	b.mu.Lock()
	b.webAuthn = w
	b.mu.Unlock()
	return w, nil
}

const backendHelp = `
WebAuthn authentication backend. Configure rp_id and rp_origins via the config endpoint,
then register users with register/begin and register/finish, and log in with login/begin and login/finish.
`
