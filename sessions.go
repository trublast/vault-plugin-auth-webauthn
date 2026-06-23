package webauthnbackend

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hashicorp/vault/sdk/logical"
)

// WebAuthn ceremonies are two-step (begin/finish). The intermediate SessionData
// is short-lived, single-use and only needs to be visible to the node that runs
// both steps. Because begin/finish are UpdateOperations, Vault forwards them to
// the local cluster's active node, so both steps always execute on the same
// node. Keeping these sessions in memory (instead of Vault storage) therefore
// avoids a storage write on every begin/finish, which under performance
// replication would otherwise be forwarded to the primary cluster's active node
// and fail when the primary is unavailable.
//
// The trade-off is that an in-flight ceremony does not survive an active-node
// restart or failover; the client simply retries. Entries also expire after
// sessionTTL and the cache is size-bounded (see maxInFlightSessions) so the
// unauthenticated begin endpoints cannot grow memory without bound.
const (
	// sessionTTL bounds how long an in-progress begin/finish ceremony may take.
	// It is also fed to the WebAuthn library (see getWebAuthn) so SessionData.Expires
	// is stamped and enforced server-side at finish.
	sessionTTL = 5 * time.Minute

	// maxInFlightSessions caps the number of concurrent in-flight ceremonies held
	// in memory per cache. The begin endpoints are unauthenticated, so this bounds
	// memory under abuse; on overflow the least-recently-used pending ceremony is
	// evicted (its owner just re-runs begin).
	maxInFlightSessions = 10000
)

// registrationSessionEntry is the in-memory value for an in-progress
// registration ceremony. pendingUser carries an ephemeral, not-yet-persisted
// user for the auto-registration flow so that nothing is written to the user
// store until register/finish succeeds.
type registrationSessionEntry struct {
	username    string
	session     *webauthn.SessionData
	pendingUser *StoredUser
}

// loginSessionEntry is the in-memory value for an in-progress login ceremony.
type loginSessionEntry struct {
	username string
	session  *webauthn.SessionData
}

// newSessionCache builds an expirable, size-bounded LRU. The cache is internally
// synchronized and lazily evicts entries older than sessionTTL, so no periodic
// tidy is required.
func newSessionCache[V any]() *lru.LRU[string, V] {
	return lru.NewLRU[string, V](maxInFlightSessions, nil, sessionTTL)
}

// The ctx and logical.Storage parameters are retained on the session helpers
// below so callers keep a single, stable interface even though the data now
// lives in memory rather than in Vault storage. They are intentionally unused.

func (b *backend) saveRegistrationSession(_ context.Context, _ logical.Storage, challenge string, username string, session *webauthn.SessionData, pendingUser *StoredUser) error {
	b.registrationSessions.Add(challenge, registrationSessionEntry{
		username:    username,
		session:     session,
		pendingUser: pendingUser,
	})
	return nil
}

func (b *backend) getRegistrationSession(_ context.Context, _ logical.Storage, challenge string) (username string, session *webauthn.SessionData, pendingUser *StoredUser, err error) {
	entry, ok := b.registrationSessions.Get(challenge)
	if !ok {
		return "", nil, nil, nil
	}
	return entry.username, entry.session, entry.pendingUser, nil
}

func (b *backend) deleteRegistrationSession(_ context.Context, _ logical.Storage, challenge string) error {
	b.registrationSessions.Remove(challenge)
	return nil
}

func (b *backend) saveLoginSession(_ context.Context, _ logical.Storage, challenge string, username string, session *webauthn.SessionData) error {
	b.loginSessions.Add(challenge, loginSessionEntry{
		username: username,
		session:  session,
	})
	return nil
}

func (b *backend) getLoginSession(_ context.Context, _ logical.Storage, challenge string) (username string, session *webauthn.SessionData, err error) {
	entry, ok := b.loginSessions.Get(challenge)
	if !ok {
		return "", nil, nil
	}
	return entry.username, entry.session, nil
}

func (b *backend) deleteLoginSession(_ context.Context, _ logical.Storage, challenge string) error {
	b.loginSessions.Remove(challenge)
	return nil
}
