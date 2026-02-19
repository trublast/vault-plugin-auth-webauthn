package webauthnbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	sessionRegistrationPrefix = "session/registration/"
	sessionLoginPrefix        = "session/login/"
	userIDIndexPrefix         = "user_id/"
)

// backend implements logical.Backend for WebAuthn authentication.
type backend struct {
	*framework.Backend

	mu           sync.RWMutex
	cachedConfig *webauthnConfig
	webAuthn     *webauthn.WebAuthn
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
	b := &backend{}
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
				pathUserPolicies(b),
				pathUserCredential(b),
				pathRegisterBegin(b),
				pathRegisterFinish(b),
				pathLoginBegin(b),
				pathLoginFinish(b),
			},
		),
		Help: strings.TrimSpace(backendHelp),
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
			Login: webauthn.TimeoutConfig{
				Timeout: 5 * time.Minute,
			},
			Registration: webauthn.TimeoutConfig{
				Timeout: 5 * time.Minute,
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

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, logical.ErrInvalidRequest
	}
	usernameRaw, ok := req.Auth.InternalData["username"]
	if !ok {
		return nil, logical.ErrInvalidRequest
	}
	username, ok := usernameRaw.(string)
	if !ok || username == "" {
		return nil, logical.ErrInvalidRequest
	}

	user, err := b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	if !policyutil.EquivalentPolicies(user.TokenPolicies, req.Auth.Policies) {
		return nil, errors.New("policies have changed, not renewing")
	}

	ttl := user.TokenTTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	maxTTL := user.TokenMaxTTL
	if maxTTL == 0 {
		maxTTL = 60 * time.Minute
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = ttl
	resp.Auth.MaxTTL = maxTTL
	resp.Auth.Period = user.TokenPeriod
	return resp, nil
}

const backendHelp = `
WebAuthn authentication backend. Configure rp_id and rp_origins via the config endpoint,
then register users with register/begin and register/finish, and log in with login/begin and login/finish.
`
