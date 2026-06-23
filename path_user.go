package webauthnbackend

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUserList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "user/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			Navigation: true,
			ItemType:   "User",
			Action:     "List",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathUserList,
				Summary:  "List registered users",
			},
		},
		HelpSynopsis:    "List WebAuthn registered users",
		HelpDescription: "Returns the list of usernames that have completed WebAuthn registration.",
	}
}

func pathUser(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "user/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			ItemType: "User",
			Action:   "Create",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Username",
			},
			"display_name": {
				Type:        framework.TypeString,
				Description: "Display name for the user (defaults to username)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathUserWrite,
				Summary:  "Create a user (pre-create for registration when auto_registration is false)",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUserWrite,
				Summary:  "Update a user",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathUserRead,
				Summary:  "Read a registered user",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathUserDelete,
				Summary:  "Delete a registered user",
			},
		},
		ExistenceCheck:  b.userExistenceCheck,
		HelpSynopsis:    "Create, update, view or delete a WebAuthn user",
		HelpDescription: "Create pre-creates a user for registration. Update modifies display_name and token parameters. Read returns user metadata and credential count. Delete removes the user and all their credentials.",
	}
	tokenutil.AddTokenFieldsWithAllowList(p.Fields, []string{
		"token_policies", "token_ttl", "token_max_ttl", "token_bound_cidrs",
		"token_no_default_policy", "token_period",
	})
	return p
}

func (b *backend) userExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	lock := b.userLock(name)
	lock.RLock()
	defer lock.RUnlock()

	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return user != nil, nil
}

func (b *backend) pathUserWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	displayName := d.Get("display_name").(string)

	lock := b.userLock(name)
	lock.Lock()
	defer lock.Unlock()

	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	created := user == nil
	if user == nil {
		// Create
		if displayName == "" {
			displayName = name
		}
		user, err = NewStoredUser(name, displayName)
		if err != nil {
			return nil, err
		}
		if _, err := user.GenerateRegistrationCode(); err != nil {
			return nil, err
		}
	}

	// Parse token fields (for both create and update)
	if err := user.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	// Update display_name if provided
	if displayName != "" {
		user.DisplayName = displayName
	}

	if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
		return nil, err
	}
	if err := b.saveUserIDIndex(ctx, req.Storage, user.ID, name); err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"username":     user.Name,
		"display_name": user.DisplayName,
	}
	if created {
		data["registration_code"] = user.RegistrationCode
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathUserList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, userPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	lock := b.userLock(name)
	lock.RLock()
	defer lock.RUnlock()

	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	credCount := len(user.Credentials)
	credIDs := make([]string, 0, credCount)
	for _, c := range user.Credentials {
		credIDs = append(credIDs, base64.RawURLEncoding.EncodeToString(c.ID))
	}
	data := map[string]interface{}{
		"username":       user.Name,
		"display_name":   user.DisplayName,
		"credentials":    credCount,
		"credential_ids": credIDs,
		"user_id_b64":    base64.RawURLEncoding.EncodeToString(user.ID),
	}
	user.PopulateTokenData(data)
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	lock := b.userLock(name)
	lock.Lock()
	defer lock.Unlock()

	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	if err := b.deleteUserIDIndex(ctx, req.Storage, user.ID); err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, userPrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func pathUserGenerateCode(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "user/" + framework.GenericNameRegex("name") + "/generate-code$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Username",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUserGenerateCode,
				Summary:  "Generate a new one-time registration code for a user",
			},
		},
		HelpSynopsis:    "Generate a WebAuthn registration code for a user",
		HelpDescription: "Generates and stores a new one-time code that must be supplied to register or re-register this user.",
	}
}

func (b *backend) pathUserGenerateCode(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	lock := b.userLock(name)
	lock.Lock()
	defer lock.Unlock()

	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user does not exist")
	}
	code, err := user.GenerateRegistrationCode()
	if err != nil {
		return nil, err
	}
	if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"username":          user.Name,
			"registration_code": code,
		},
	}, nil
}

func pathUserPolicies(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "user/" + framework.GenericNameRegex("name") + "/policies$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Username",
			},
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of policies for the generated token",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUserPoliciesUpdate,
				Summary:  "Update user token policies",
			},
		},
		HelpSynopsis:    "Update token policies for a user",
		HelpDescription: "Updates the policies that will apply to tokens generated when this user logs in.",
	}
}

func (b *backend) pathUserPoliciesUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	lock := b.userLock(name)
	lock.Lock()
	defer lock.Unlock()

	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user does not exist")
	}
	user.TokenPolicies = policyutil.ParsePolicies(d.Get("token_policies"))
	return nil, b.saveStoredUser(ctx, req.Storage, user)
}

func pathUserCredential(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "user/" + framework.GenericNameRegex("name") + "/credential/" + framework.GenericNameRegex("credential_id"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Username",
			},
			"credential_id": {
				Type:        framework.TypeString,
				Description: "Credential ID (base64url encoded)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathUserCredentialDelete,
				Summary:  "Remove a credential from a user",
			},
		},
		HelpSynopsis:    "Remove a WebAuthn credential from a user",
		HelpDescription: "Removes a single credential (e.g. lost key) from the user. The credential_id is the base64url-encoded credential ID.",
	}
}

func (b *backend) pathUserCredentialDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	credIDStr := d.Get("credential_id").(string)
	if credIDStr == "" {
		return logical.ErrorResponse("credential_id is required"), nil
	}
	credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
	if err != nil {
		return logical.ErrorResponse("invalid credential_id: must be base64url encoded"), nil
	}

	lock := b.userLock(name)
	lock.Lock()
	defer lock.Unlock()

	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	if !user.RemoveCredentialByID(credID) {
		return logical.ErrorResponse("credential not found"), nil
	}

	if err := b.saveStoredUser(ctx, req.Storage, user); err != nil {
		return nil, err
	}

	return nil, nil
}
