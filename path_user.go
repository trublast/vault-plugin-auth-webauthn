package webauthnbackend

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUserList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "user/?$",
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
	return &framework.Path{
		Pattern: "user/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Username",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathUserRead,
				Summary:  "Read a registered user",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathUserDelete,
				Summary:  "Delete a registered user",
			},
		},
		HelpSynopsis:    "View or delete a WebAuthn registered user",
		HelpDescription: "Read returns user metadata and credential count. Delete removes the user and all their credentials.",
	}
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
	user, err := b.getStoredUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	credCount := len(user.Credentials)
	// Не отдаём секретные данные (ключи, attestation), только метаданные
	data := map[string]interface{}{
		"username":      user.Name,
		"display_name":  user.DisplayName,
		"credentials":   credCount,
		"user_id_b64":   base64.RawURLEncoding.EncodeToString(user.ID),
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
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
