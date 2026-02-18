package webauthnbackend

const configPath = "config"

// webauthnConfig is stored in Vault and used to build webauthn.Config.
type webauthnConfig struct {
	RPID          string   `json:"rp_id"`
	RPDisplayName string   `json:"rp_display_name"`
	RPOrigins     []string `json:"rp_origins"`
}
