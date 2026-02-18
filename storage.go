package webauthnbackend

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) saveUserIDIndex(ctx context.Context, s logical.Storage, userID []byte, username string) error {
	if len(userID) == 0 {
		return nil
	}
	key := userIDIndexPrefix + base64.RawURLEncoding.EncodeToString(userID)
	entry, err := logical.StorageEntryJSON(key, map[string]string{"username": username})
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *backend) getUsernameByUserHandle(ctx context.Context, s logical.Storage, userHandle []byte) (string, error) {
	if len(userHandle) == 0 {
		return "", nil
	}
	key := userIDIndexPrefix + base64.RawURLEncoding.EncodeToString(userHandle)
	entry, err := s.Get(ctx, key)
	if err != nil || entry == nil {
		return "", err
	}
	var raw map[string]string
	if err := entry.DecodeJSON(&raw); err != nil {
		return "", err
	}
	return raw["username"], nil
}

func (b *backend) deleteUserIDIndex(ctx context.Context, s logical.Storage, userID []byte) error {
	if len(userID) == 0 {
		return nil
	}
	key := userIDIndexPrefix + base64.RawURLEncoding.EncodeToString(userID)
	return s.Delete(ctx, key)
}

func (b *backend) getStoredUser(ctx context.Context, s logical.Storage, username string) (*StoredUser, error) {
	key := userPrefix + username
	entry, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var u StoredUser
	if err := entry.DecodeJSON(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (b *backend) saveStoredUser(ctx context.Context, s logical.Storage, u *StoredUser) error {
	entry, err := logical.StorageEntryJSON(u.storageKey(), u)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// sessionRegistrationEntry stores registration session and username for lookup on finish.
type sessionRegistrationEntry struct {
	Username string            `json:"username"`
	Session  *webauthn.SessionData `json:"session"`
}

func (b *backend) saveRegistrationSession(ctx context.Context, s logical.Storage, challenge string, username string, session *webauthn.SessionData) error {
	key := sessionRegistrationPrefix + challenge
	entry, err := logical.StorageEntryJSON(key, &sessionRegistrationEntry{Username: username, Session: session})
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *backend) getRegistrationSession(ctx context.Context, s logical.Storage, challenge string) (username string, session *webauthn.SessionData, err error) {
	key := sessionRegistrationPrefix + challenge
	entry, err := s.Get(ctx, key)
	if err != nil || entry == nil {
		return "", nil, err
	}
	var raw map[string]interface{}
	if err := entry.DecodeJSON(&raw); err != nil {
		return "", nil, err
	}
	if u, ok := raw["username"].(string); ok {
		username = u
	}
	sessionRaw, ok := raw["session"]
	if !ok {
		return username, nil, nil
	}
	sessionBytes, err := json.Marshal(sessionRaw)
	if err != nil {
		return username, nil, err
	}
	var sdata webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &sdata); err != nil {
		return username, nil, err
	}
	return username, &sdata, nil
}

func (b *backend) deleteRegistrationSession(ctx context.Context, s logical.Storage, challenge string) error {
	return s.Delete(ctx, sessionRegistrationPrefix+challenge)
}

// sessionLoginEntry stores login session and username for lookup on finish.
type sessionLoginEntry struct {
	Username string            `json:"username"`
	Session  *webauthn.SessionData `json:"session"`
}

func (b *backend) saveLoginSession(ctx context.Context, s logical.Storage, challenge string, username string, session *webauthn.SessionData) error {
	key := sessionLoginPrefix + challenge
	entry, err := logical.StorageEntryJSON(key, &sessionLoginEntry{Username: username, Session: session})
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *backend) getLoginSession(ctx context.Context, s logical.Storage, challenge string) (username string, session *webauthn.SessionData, err error) {
	key := sessionLoginPrefix + challenge
	entry, err := s.Get(ctx, key)
	if err != nil || entry == nil {
		return "", nil, err
	}
	var raw map[string]interface{}
	if err := entry.DecodeJSON(&raw); err != nil {
		return "", nil, err
	}
	if u, ok := raw["username"].(string); ok {
		username = u
	}
	sessionRaw, ok := raw["session"]
	if !ok {
		return username, nil, nil
	}
	sessionBytes, err := json.Marshal(sessionRaw)
	if err != nil {
		return username, nil, err
	}
	var sdata webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &sdata); err != nil {
		return username, nil, err
	}
	return username, &sdata, nil
}

func (b *backend) deleteLoginSession(ctx context.Context, s logical.Storage, challenge string) error {
	return s.Delete(ctx, sessionLoginPrefix+challenge)
}
