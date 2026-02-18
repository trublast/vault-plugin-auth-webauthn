package webauthnbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathLoginBegin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login/begin$",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username to authenticate (omit for discoverable/passkey flow: browser will show passkey picker)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginBegin,
				Summary:  "Start WebAuthn login",
			},
		},
		HelpSynopsis:    "Begin WebAuthn login",
		HelpDescription: "With username: returns options for that user. Without username (discoverable): returns options for passkey picker; user is identified by userHandle in login/finish.",
	}
}

func pathLoginFinish(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login/finish$",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username (omit if using discoverable flow; user is identified from assertion userHandle)",
			},
			"credential": {
				Type:        framework.TypeMap,
				Description: "Assertion response from the authenticator (PublicKeyCredential with response)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginFinish,
				Summary:  "Finish WebAuthn login",
			},
		},
		HelpSynopsis:    "Complete WebAuthn login",
		HelpDescription: "Submit the assertion response to complete login and receive a Vault auth token.",
	}
}

func (b *backend) pathLoginBegin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	w, err := b.getWebAuthn(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return logical.ErrorResponse("WebAuthn not configured: set rp_id and rp_origins via config first"), nil
	}

	username := strings.TrimSpace(d.Get("username").(string))

	if username == "" {
		// Discoverable (passkey) flow: no allowCredentials, browser shows passkey picker
		assertion, session, err := w.BeginDiscoverableLogin()
		if err != nil {
			return logical.ErrorResponse("failed to begin discoverable login: %v", err), nil
		}
		if err := b.saveLoginSession(ctx, req.Storage, session.Challenge, "", session); err != nil {
			return nil, err
		}
		assertionJSON, err := json.Marshal(assertion)
		if err != nil {
			return nil, err
		}
		var data map[string]interface{}
		if err := json.Unmarshal(assertionJSON, &data); err != nil {
			return nil, err
		}
		return &logical.Response{Data: data}, nil
	}

	// Username-based flow
	user, err := b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return logical.ErrorResponse("user is not registered"), nil
	}
	if len(user.WebAuthnCredentials()) == 0 {
		return logical.ErrorResponse("user has no credentials"), nil
	}

	assertion, session, err := w.BeginLogin(user)
	if err != nil {
		return logical.ErrorResponse("failed to begin login: %v", err), nil
	}

	challenge := session.Challenge
	if err := b.saveLoginSession(ctx, req.Storage, challenge, username, session); err != nil {
		return nil, err
	}

	assertionJSON, err := json.Marshal(assertion)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(assertionJSON, &data); err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathLoginFinish(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	w, err := b.getWebAuthn(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return logical.ErrorResponse("WebAuthn not configured"), nil
	}

	username := strings.TrimSpace(d.Get("username").(string))
	credMap, ok := d.GetOk("credential")
	if !ok {
		return logical.ErrorResponse("credential is required"), nil
	}
	credentialMap := credMap.(map[string]interface{})

	credBytes, err := json.Marshal(credentialMap)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credBytes))
	if err != nil {
		return logical.ErrorResponse("invalid credential response: %v", err), nil
	}

	challenge := parsed.Response.CollectedClientData.Challenge
	loginUsername, session, err := b.getLoginSession(ctx, req.Storage, challenge)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return logical.ErrorResponse("login session expired or not found"), nil
	}
	defer func() { _ = b.deleteLoginSession(ctx, req.Storage, challenge) }()

	var user *StoredUser
	if loginUsername == "" {
		// Discoverable flow: resolve user from userHandle in assertion
		handler := func(_, userHandle []byte) (webauthn.User, error) {
			un, err := b.getUsernameByUserHandle(ctx, req.Storage, userHandle)
			if err != nil {
				return nil, err
			}
			if un == "" {
				return nil, fmt.Errorf("user not found for userHandle")
			}
			u, err := b.getStoredUser(ctx, req.Storage, un)
			if err != nil {
				return nil, err
			}
			if u == nil {
				return nil, fmt.Errorf("user not found")
			}
			return u, nil
		}
		discoveredUser, credential, err := w.ValidatePasskeyLogin(handler, *session, parsed)
		if err != nil {
			return logical.ErrorResponse("discoverable login validation failed: %v", err), nil
		}
		user = discoveredUser.(*StoredUser)
		username = user.Name
		// Update stored credential sign count
		for i := range user.Credentials {
			if bytes.Equal(user.Credentials[i].ID, credential.ID) {
				user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
				break
			}
		}
		if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
			b.Logger().Warn("failed to update credential sign count", "error", err)
		}
		return b.loginSuccessResponse(username, credential)
	}

	// Username-based flow
	if username == "" {
		username = loginUsername
	}
	if loginUsername != username {
		return logical.ErrorResponse("username does not match login session"), nil
	}

	user, err = b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return logical.ErrorResponse("user not found"), nil
	}

	credential, err := w.ValidateLogin(user, *session, parsed)
	if err != nil {
		return logical.ErrorResponse("login validation failed: %v", err), nil
	}

	// Update stored credential sign count
	for i := range user.Credentials {
		if bytes.Equal(user.Credentials[i].ID, credential.ID) {
			user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
			break
		}
	}
	if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
		b.Logger().Warn("failed to update credential sign count", "error", err)
	}

	return b.loginSuccessResponse(username, credential)
}

func (b *backend) loginSuccessResponse(username string, credential *webauthn.Credential) (*logical.Response, error) {
	return &logical.Response{
		Auth: &logical.Auth{
			DisplayName: username,
			Alias: &logical.Alias{
				Name: username,
				Metadata: map[string]string{
					"username": username,
				},
			},
			Metadata: map[string]string{
				"username":                 username,
				"attestation_type":         credential.AttestationType,
				"authenticator_sign_count": fmt.Sprintf("%d", credential.Authenticator.SignCount),
			},
			InternalData: map[string]interface{}{
				"username": username,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       30 * time.Second,
				MaxTTL:    60 * time.Minute,
				Renewable: true,
			},
			Policies: []string{"default"},
		},
	}, nil
}
