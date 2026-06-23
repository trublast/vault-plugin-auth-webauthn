package webauthnbackend

import (
	"context"
	"encoding/base64"

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
