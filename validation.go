package webauthnbackend

import (
	"errors"
)

const maxUsernameLen = 256

// errInvalidUsername is returned when username contains path traversal or invalid chars.
var errInvalidUsername = errors.New("username contains invalid characters")

// Unified error messages to prevent user enumeration.
const (
	msgLoginFailed       = "login failed"
	msgRegistrationFailed = "registration failed"
)

// validateUsername returns error if username contains disallowed characters.
// Allowed: letters (a-z, A-Z), digits (0-9), and - _ @ .
func validateUsername(username string) error {
	if len(username) > maxUsernameLen {
		return errors.New("username too long")
	}
	for _, c := range username {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '@' || c == '.' {
			continue
		}
		return errInvalidUsername
	}
	return nil
}


