package config

import (
	"flag"
	"os"
	"strconv"
)

// Config holds all application configuration.
type Config struct {
	Port     int
	DataFile string
	DevMode  bool
	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string
}

// Load reads configuration from defaults < env < flags.
func Load() *Config {
	cfg := &Config{
		Port:     8470,
		DataFile: "jwtkit.json",
		DevMode:  true,
	}

	// Env overrides defaults
	if v := os.Getenv("JWTKIT_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Port = p
		}
	}
	if v := os.Getenv("JWTKIT_DATA_FILE"); v != "" {
		cfg.DataFile = v
	}
	if v := os.Getenv("JWTKIT_SMTP_HOST"); v != "" {
		cfg.SMTPHost = v
		cfg.DevMode = false
	}
	cfg.SMTPPort = envInt("JWTKIT_SMTP_PORT", 587)
	cfg.SMTPUser = os.Getenv("JWTKIT_SMTP_USER")
	cfg.SMTPPass = os.Getenv("JWTKIT_SMTP_PASS")
	cfg.SMTPFrom = os.Getenv("JWTKIT_SMTP_FROM")
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = "noreply@jwtkit.local"
	}

	// Flags override env
	flag.IntVar(&cfg.Port, "port", cfg.Port, "HTTP port")
	flag.StringVar(&cfg.DataFile, "data", cfg.DataFile, "Data file path")
	flag.BoolVar(&cfg.DevMode, "dev", cfg.DevMode, "Dev mode (returns OTP in response)")
	flag.Parse()

	return cfg
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
