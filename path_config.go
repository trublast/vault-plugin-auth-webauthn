package webauthnbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		DisplayAttrs: &framework.DisplayAttributes{
			Action: "Configure",
		},
		Fields: map[string]*framework.FieldSchema{
			"rp_id": {
				Type:        framework.TypeString,
				Description: "Relying Party ID (e.g. localhost or your domain). Must match the origin's host.",
			},
			"rp_display_name": {
				Type:        framework.TypeString,
				Description: "Human-readable name for the Relying Party.",
			},
			"rp_origins": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Allowed origins for WebAuthn (e.g. https://vault.example.com, http://localhost:8200).",
			},
			"auto_registration": {
				Type:        framework.TypeBool,
				Description: "If true (default), new users can self-register. If false, only pre-created users (via user/ path) can register.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read WebAuthn configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Configure WebAuthn backend",
			},
		},
		HelpSynopsis:    "Configure the WebAuthn authentication backend",
		HelpDescription: "Configure rp_id, rp_display_name, and rp_origins for the WebAuthn Relying Party.",
	}
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	data := map[string]interface{}{
		"rp_id":           cfg.RPID,
		"rp_display_name": cfg.RPDisplayName,
		"rp_origins":      cfg.RPOrigins,
		"auto_registration": cfg.autoRegistrationEnabled(),
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	existing, _ := b.config(ctx, req.Storage)
	cfg := &webauthnConfig{}
	if existing != nil {
		cfg.RPID = existing.RPID
		cfg.RPDisplayName = existing.RPDisplayName
		cfg.RPOrigins = existing.RPOrigins
		cfg.AutoRegistration = existing.AutoRegistration
	}
	if v, ok := d.GetOk("rp_id"); ok {
		cfg.RPID = v.(string)
	}
	if v, ok := d.GetOk("rp_display_name"); ok {
		cfg.RPDisplayName = v.(string)
	}
	if v, ok := d.GetOk("rp_origins"); ok && v != nil {
		if sl, ok := v.([]string); ok {
			cfg.RPOrigins = sl
		}
	}
	if v, ok := d.GetOk("auto_registration"); ok {
		val := v.(bool)
		cfg.AutoRegistration = &val
	}
	if cfg.RPID == "" {
		return logical.ErrorResponse("rp_id is required"), nil
	}
	if len(cfg.RPOrigins) == 0 {
		return logical.ErrorResponse("at least one rp_origins value is required"), nil
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = cfg.RPID
	}
	entry, err := logical.StorageEntryJSON(configPath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	b.invalidateConfig()
	return nil, nil
}
