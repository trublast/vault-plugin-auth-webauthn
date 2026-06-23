package webauthnbackend

const configPath = "config"

// webauthnConfig is stored in Vault and used to build webauthn.Config.
type webauthnConfig struct {
	RPID             string   `json:"rp_id"`
	RPDisplayName    string   `json:"rp_display_name"`
	RPOrigins        []string `json:"rp_origins"`
	AutoRegistration *bool    `json:"auto_registration,omitempty"`
}

// autoRegistrationEnabled returns true if auto-registration is enabled.
func (c *webauthnConfig) autoRegistrationEnabled() bool {
	if c == nil || c.AutoRegistration == nil {
		return false
	}
	return *c.AutoRegistration
}
