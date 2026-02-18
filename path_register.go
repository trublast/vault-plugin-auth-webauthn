package webauthnbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

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
			"username": {
				Type:        framework.TypeString,
				Description: "Username being registered",
			},
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

	username := strings.TrimSpace(d.Get("username").(string))
	if username == "" {
		return logical.ErrorResponse("username is required"), nil
	}

	user, err := b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		user, err = NewStoredUser(username, username)
		if err != nil {
			return nil, err
		}
		if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
			return nil, err
		}
		if err := b.saveUserIDIndex(ctx, req.Storage, user.ID, username); err != nil {
			return nil, err
		}
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(user.CredentialExcludeList()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		}),
	}
	creation, session, err := w.BeginRegistration(user, opts...)
	if err != nil {
		return logical.ErrorResponse("failed to begin registration: %v", err), nil
	}

	if err := b.saveRegistrationSession(ctx, req.Storage, session.Challenge, username, session); err != nil {
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

	username := strings.TrimSpace(d.Get("username").(string))
	if username == "" {
		return logical.ErrorResponse("username is required"), nil
	}
	credMap, ok := d.GetOk("credential")
	if !ok {
		return logical.ErrorResponse("credential is required"), nil
	}
	credentialMap := credMap.(map[string]interface{})

	user, err := b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return logical.ErrorResponse("user not found or registration not started"), nil
	}

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
	regUsername, session, err := b.getRegistrationSession(ctx, req.Storage, challenge)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return logical.ErrorResponse("registration session expired or not found"), nil
	}
	if regUsername != username {
		return logical.ErrorResponse("username does not match registration session"), nil
	}
	defer func() { _ = b.deleteRegistrationSession(ctx, req.Storage, challenge) }()

	credential, err := w.CreateCredential(user, *session, parsed)
	if err != nil {
		return logical.ErrorResponse("failed to create credential: %v", err), nil
	}

	user.AddCredential(*credential)
	if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username": username,
			"message":  "registration successful",
		},
	}, nil
}
