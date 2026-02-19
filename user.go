package webauthnbackend

import (
	"bytes"
	"crypto/rand"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
)

const userPrefix = "user/"

// StoredUser implements webauthn.User and is persisted in Vault storage.
type StoredUser struct {
	tokenutil.TokenParams

	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"display_name"`
	Credentials []webauthn.Credential `json:"credentials"`
}

// NewStoredUser creates a new user with a random ID.
func NewStoredUser(name, displayName string) (*StoredUser, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	return &StoredUser{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Credentials: nil,
	}, nil
}

func randomID() ([]byte, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WebAuthnID returns the user's ID.
func (u *StoredUser) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's name.
func (u *StoredUser) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name.
func (u *StoredUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials returns credentials owned by the user.
func (u *StoredUser) WebAuthnCredentials() []webauthn.Credential {
	if u.Credentials == nil {
		return nil
	}
	return u.Credentials
}

// AddCredential adds a credential to the user.
func (u *StoredUser) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// RemoveCredentialByID removes a credential by its ID. Returns true if removed.
func (u *StoredUser) RemoveCredentialByID(id []byte) bool {
	for i, c := range u.Credentials {
		if bytes.Equal(c.ID, id) {
			u.Credentials = append(u.Credentials[:i], u.Credentials[i+1:]...)
			return true
		}
	}
	return false
}

// CredentialExcludeList returns descriptors for credentials to exclude from registration.
func (u *StoredUser) CredentialExcludeList() []protocol.CredentialDescriptor {
	list := make([]protocol.CredentialDescriptor, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		list = append(list, c.Descriptor())
	}
	return list
}

// storageKey returns the Vault storage key for this user.
func (u *StoredUser) storageKey() string {
	return userPrefix + u.Name
}
