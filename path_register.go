package webauthnbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRegisterBegin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "register/begin$",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username to register for WebAuthn",
			},
			"registration_code": {
				Type:        framework.TypeString,
				Description: "One-time registration code returned when the user was created",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRegisterBegin,
				Summary:  "Start WebAuthn registration",
			},
		},
		HelpSynopsis:    "Begin WebAuthn registration for a user",
		HelpDescription: "Returns PublicKeyCredentialCreationOptions for the client. Call register/finish with the credential response to complete registration.",
	}
}

func pathRegisterFinish(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "register/finish$",
		Fields: map[string]*framework.FieldSchema{
			"credential": {
				Type:        framework.TypeMap,
				Description: "Credential creation response from the authenticator (PublicKeyCredential with response)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRegisterFinish,
				Summary:  "Finish WebAuthn registration",
			},
		},
		HelpSynopsis:    "Complete WebAuthn registration",
		HelpDescription: "Submit the credential creation response from the client to complete registration.",
	}
}

func (b *backend) pathRegisterBegin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	w, err := b.getWebAuthn(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return logical.ErrorResponse("WebAuthn not configured: set rp_id and rp_origins via config first"), nil
	}

	usernameRaw, ok := d.GetOk("username")
	if !ok || usernameRaw == nil {
		return logical.ErrorResponse("username is required"), nil
	}
	username := strings.TrimSpace(usernameRaw.(string))
	if username == "" {
		return logical.ErrorResponse("username is required"), nil
	}
	if err := validateUsername(username); err != nil {
		return logical.ErrorResponse("invalid username: %v", err), nil
	}
	var registrationCode string
	if v, ok := d.GetOk("registration_code"); ok && v != nil {
		registrationCode = strings.TrimSpace(v.(string))
	}

	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	lock := b.userLock(username)
	lock.Lock()
	defer lock.Unlock()

	user, err := b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}

	// pendingUser is set only for the auto-registration flow. It carries an
	// ephemeral, unpersisted user through the session so that nothing is written
	// to the user store until register/finish succeeds. This prevents an
	// unauthenticated begin call from creating permanent (and credential-less)
	// user records or user_id index entries.
	var pendingUser *StoredUser
	if user == nil {
		if !cfg.autoRegistrationEnabled() {
			return logical.ErrorResponse(msgRegistrationFailed), nil
		}
		user, err = NewStoredUser(username, username)
		if err != nil {
			return nil, err
		}
		pendingUser = user
	} else if !user.RegistrationCodeMatches(registrationCode, time.Now()) {
		return logical.ErrorResponse(msgRegistrationFailed), nil
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(user.CredentialExcludeList()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExtensions(protocol.AuthenticationExtensions{"credProps": true}),
	}
	creation, session, err := w.BeginRegistration(user, opts...)
	if err != nil {
		return logical.ErrorResponse("failed to begin registration: %v", err), nil
	}

	if err := b.saveRegistrationSession(ctx, req.Storage, session.Challenge, username, session, pendingUser); err != nil {
		return nil, err
	}

	// Return creation options as response data (client expects JSON-compatible map).
	creationJSON, err := json.Marshal(creation)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(creationJSON, &data); err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathRegisterFinish(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	w, err := b.getWebAuthn(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return logical.ErrorResponse("WebAuthn not configured"), nil
	}

	credMap, ok := d.GetOk("credential")
	if !ok {
		return logical.ErrorResponse("credential is required"), nil
	}
	credentialMap := credMap.(map[string]interface{})

	// Get session by challenge from the credential response.
	// Client sends the same payload as in the browser; response has clientDataJSON which contains challenge.
	credBytes, err := json.Marshal(credentialMap)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credBytes))
	if err != nil {
		return logical.ErrorResponse("invalid credential response: %v", err), nil
	}

	// Challenge is in the session we stored at begin. We need to find session by challenge from parsed response.
	challenge := parsed.Response.CollectedClientData.Challenge

	// Peek the session (keyed by the random challenge) to learn which user we
	// must lock. The challenge->username mapping is immutable, so this read is
	// only used to pick the per-user lock; the authoritative read happens under
	// the lock below.
	username, _, _, err := b.getRegistrationSession(ctx, req.Storage, challenge)
	if err != nil {
		return nil, err
	}
	if username == "" {
		return logical.ErrorResponse(msgRegistrationFailed), nil
	}

	lock := b.userLock(username)
	lock.Lock()
	defer lock.Unlock()

	// Authoritative read under the user lock. Deleting the session under the
	// same lock guarantees a concurrent finish for the same challenge observes
	// it as already consumed (single-use), so a credential cannot be added twice.
	username, session, pendingUser, err := b.getRegistrationSession(ctx, req.Storage, challenge)
	if err != nil {
		return nil, err
	}
	if session == nil || username == "" {
		return logical.ErrorResponse(msgRegistrationFailed), nil
	}
	defer func() { _ = b.deleteRegistrationSession(ctx, req.Storage, challenge) }()

	user, err := b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}

	// isNewUser is true for the auto-registration flow: the user was not
	// persisted at begin and is materialized here from the pending data carried
	// in the session. We are holding the per-user lock and just confirmed the
	// user does not exist, so creating it now is race-free. If the user is
	// absent and there is no pending user, this was a re-registration whose
	// target user has since been removed, so reject.
	isNewUser := false
	if user == nil {
		if pendingUser == nil {
			return logical.ErrorResponse(msgRegistrationFailed), nil
		}
		user = pendingUser
		isNewUser = true
	}

	credential, err := w.CreateCredential(user, *session, parsed)
	if err != nil {
		return logical.ErrorResponse(msgRegistrationFailed), nil
	}

	user.AddCredential(*credential)
	user.RegistrationCode = ""
	user.RegistrationCodeCreatedAt = time.Time{}
	if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
		return nil, err
	}
	if isNewUser {
		if err := b.saveUserIDIndex(ctx, req.Storage, user.ID, username); err != nil {
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username": username,
			"message":  "registration successful",
		},
	}, nil
}
