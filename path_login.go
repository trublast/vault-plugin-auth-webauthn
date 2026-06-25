package webauthnbackend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathLoginBegin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login/begin$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixWebAuthn,
			OperationVerb:   "begin",
			OperationSuffix: "login",
		},
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
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: http.StatusText(http.StatusOK),
						Fields: map[string]*framework.FieldSchema{
							"publicKey": {
								Type:        framework.TypeMap,
								Required:    true,
								Description: "PublicKeyCredentialRequestOptions for navigator.credentials.get()",
							},
							"mediation": {
								Type:        framework.TypeString,
								Description: "Optional credential mediation requirement",
							},
						},
					}},
				},
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathLoginAliasLookahead,
			},
		},
		HelpSynopsis:    "Begin WebAuthn login",
		HelpDescription: "With username: returns options for that user. Without username (discoverable): returns options for passkey picker; user is identified by userHandle in login/finish.",
	}
}

func pathLoginFinish(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login/finish$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixWebAuthn,
			OperationVerb:   "finish",
			OperationSuffix: "login",
		},
		Fields: map[string]*framework.FieldSchema{
			"credential": {
				Type:        framework.TypeMap,
				Description: "Assertion response from the authenticator (PublicKeyCredential with response)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginFinish,
				Summary:  "Finish WebAuthn login",
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: http.StatusText(http.StatusOK),
					}},
				},
			},
		},
		HelpSynopsis:    "Complete WebAuthn login",
		HelpDescription: "Submit the assertion response to complete login and receive a Vault auth token.",
	}
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	usernameRaw, ok := d.GetOk("username")
	if !ok {
		return nil, errors.New("missing username")
	}
	username := strings.TrimSpace(usernameRaw.(string))
	if username == "" {
		return nil, errors.New("missing username")
	}
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}

func (b *backend) pathLoginBegin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	w, err := b.getWebAuthn(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return logical.ErrorResponse("WebAuthn not configured: set rp_id and rp_origins via config first"), nil
	}

	var username string
	if v, ok := d.GetOk("username"); ok && v != nil {
		username = strings.TrimSpace(v.(string))
	}

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
	if err := validateUsername(username); err != nil {
		return logical.ErrorResponse("invalid username: %v", err), nil
	}
	lock := b.userLock(username)
	lock.RLock()
	defer lock.RUnlock()

	user, err := b.getStoredUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	if user == nil || len(user.WebAuthnCredentials()) == 0 {
		return logical.ErrorResponse(msgLoginFailed), nil
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

	// Peek the session (keyed by the random challenge) to discover which user
	// we must lock. For the discoverable flow the session has no username, so
	// resolve it from the assertion's userHandle. This read only selects the
	// per-user lock; the authoritative read happens under the lock below.
	loginUsername, peekSession, err := b.getLoginSession(ctx, req.Storage, challenge)
	if err != nil {
		return nil, err
	}
	if peekSession == nil {
		return logical.ErrorResponse(msgLoginFailed), nil
	}

	lockKey := loginUsername
	if lockKey == "" {
		un, err := b.getUsernameByUserHandle(ctx, req.Storage, parsed.Response.UserHandle)
		if err != nil {
			return nil, err
		}
		if un == "" {
			return logical.ErrorResponse(msgLoginFailed), nil
		}
		lockKey = un
	}

	lock := b.userLock(lockKey)
	lock.Lock()
	defer lock.Unlock()

	// Authoritative read under the user lock. The challenge->username mapping is
	// immutable, so loginUsername from the peek above stays valid; we only re-read
	// the session here and delete it under the same lock so a concurrent finish
	// for the same challenge sees it as already consumed (single-use).
	_, session, err := b.getLoginSession(ctx, req.Storage, challenge)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return logical.ErrorResponse(msgLoginFailed), nil
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
			return logical.ErrorResponse(msgLoginFailed), nil
		}
		user = discoveredUser.(*StoredUser)
		if resp := b.finalizeCredential(ctx, req.Storage, user, credential); resp != nil {
			return resp, nil
		}
		return b.loginSuccessResponse(ctx, req, user, credential)
	}

	// Username-based flow: user is identified by the session (keyed by challenge).
	// loginUsername was already validated in pathLoginBegin before being stored.
	user, err = b.getStoredUser(ctx, req.Storage, loginUsername)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return logical.ErrorResponse(msgLoginFailed), nil
	}

	credential, err := w.ValidateLogin(user, *session, parsed)
	if err != nil {
		return logical.ErrorResponse(msgLoginFailed), nil
	}

	if resp := b.finalizeCredential(ctx, req.Storage, user, credential); resp != nil {
		return resp, nil
	}

	return b.loginSuccessResponse(ctx, req, user, credential)
}

// finalizeCredential performs the post-validation bookkeeping shared by both
// login flows. The WebAuthn library flags Authenticator.CloneWarning when the
// assertion's signature counter did not advance past the stored value (and both
// are not zero), which signals a possibly cloned authenticator or a replay. In
// that case it also leaves SignCount unchanged. For an auth backend we treat
// this as a hard failure rather than silently accepting the login. Otherwise we
// persist the advanced sign count so the next regression can be detected.
//
// A non-nil response means the login must be rejected with that response.
func (b *backend) finalizeCredential(ctx context.Context, s logical.Storage, user *StoredUser, credential *webauthn.Credential) *logical.Response {
	if credential.Authenticator.CloneWarning {
		b.Logger().Warn("rejecting login: possible cloned authenticator (sign counter did not advance)",
			"username", user.Name,
			"credential_id", base64.RawURLEncoding.EncodeToString(credential.ID),
		)
		return logical.ErrorResponse(msgLoginFailed)
	}
	// Should we update the sign count? Potetial problem with perfomance replication.
	// for i := range user.Credentials {
	// 	if bytes.Equal(user.Credentials[i].ID, credential.ID) {
	// 		user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
	// 		break
	// 	}
	// }
	// if err := b.saveStoredUser(ctx, s, user); err != nil {
	// 	b.Logger().Warn("failed to update credential sign count", "error", err)
	// }
	return nil
}

func (b *backend) loginSuccessResponse(ctx context.Context, req *logical.Request, user *StoredUser, credential *webauthn.Credential) (*logical.Response, error) {
	auth := &logical.Auth{
		DisplayName: user.Name,
		Alias: &logical.Alias{
			Name: user.Name,
			Metadata: map[string]string{
				"username": user.Name,
			},
		},
		Metadata: map[string]string{
			"username":                 user.Name,
			"attestation_type":         credential.AttestationType,
			"authenticator_sign_count": fmt.Sprintf("%d", credential.Authenticator.SignCount),
		},
		InternalData: map[string]interface{}{
			"username": user.Name,
		},
	}
	user.PopulateTokenAuth(auth)

	if len(user.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, user.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	if len(auth.Policies) == 0 && !auth.NoDefaultPolicy {
		auth.Policies = []string{"default"}
	}
	return &logical.Response{Auth: auth}, nil
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
	if err := validateUsername(username); err != nil {
		return nil, logical.ErrInvalidRequest
	}

	lock := b.userLock(username)
	lock.RLock()
	defer lock.RUnlock()

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

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = user.TokenTTL
	resp.Auth.MaxTTL = user.TokenMaxTTL
	resp.Auth.Period = user.TokenPeriod
	return resp, nil
}
