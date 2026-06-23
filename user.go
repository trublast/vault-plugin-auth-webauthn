package webauthnbackend

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
)

const userPrefix = "user/"
const registrationCodeBytes = 32

// registrationCodeTTL is how long a one-time registration code remains valid.
const registrationCodeTTL = 7 * 24 * time.Hour

// StoredUser implements webauthn.User and is persisted in Vault storage.
type StoredUser struct {
	tokenutil.TokenParams

	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"display_name"`
	Credentials []webauthn.Credential `json:"credentials"`

	RegistrationCode          string    `json:"registration_code,omitempty"`
	RegistrationCodeCreatedAt time.Time `json:"registration_code_created_at,omitempty"`
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
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func generateRegistrationCode() (string, error) {
	buf := make([]byte, registrationCodeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateRegistrationCode creates a new one-time code required for registration.
func (u *StoredUser) GenerateRegistrationCode() (string, error) {
	code, err := generateRegistrationCode()
	if err != nil {
		return "", err
	}
	u.RegistrationCode = code
	u.RegistrationCodeCreatedAt = time.Now().UTC()
	return code, nil
}

// RegistrationCodeMatches returns true when code matches the current one-time code
// and the code has not expired.
func (u *StoredUser) RegistrationCodeMatches(code string, now time.Time) bool {
	if u == nil || u.RegistrationCode == "" || code == "" {
		return false
	}
	if u.RegistrationCodeCreatedAt.IsZero() || now.Sub(u.RegistrationCodeCreatedAt) > registrationCodeTTL {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(u.RegistrationCode), []byte(code)) == 1
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
