package config

import (
	"flag"
	"os"
	"strings"
	"time"
)

// Config holds application configuration parameters.
type Config struct {
	// Splunk HEC receiver settings
	HECAddr  string // HTTP listen address for Splunk HEC
	HECToken string // Splunk HEC token

	// Splunk REST API settings for history fetch
	SplunkURL     string   // Base URL for Splunk REST API (e.g. https://splunk:8089)
	SplunkToken   string   // Splunk REST API token or "user:pass"
	SplunkIndexes []string // Indexes to query for history (comma-separated)

	// Responder settings
	IPTablesChain string // iptables chain name for blocking

	// Engine settings
	Tier2TTL time.Duration // duration before auto-unblock of Tier 2 blocks
}

// LoadConfig parses flags and environment variables to build Config.
func LoadConfig() *Config {
	cfg := &Config{}

	// Receiver
	flag.StringVar(&cfg.HECAddr, "hec-addr", getEnv("HEC_ADDR", ":8080"), "Splunk HEC listen address")
	flag.StringVar(&cfg.HECToken, "hec-token", getEnv("HEC_TOKEN", ""), "Splunk HEC token")

	// Fetcher
	flag.StringVar(&cfg.SplunkURL, "splunk-url", getEnv("SPLUNK_URL", "https://localhost:8089"), "Splunk REST API URL")
	flag.StringVar(&cfg.SplunkToken, "splunk-token", getEnv("SPLUNK_TOKEN", ""), "Splunk REST API token or user:pass")
	indexes := flag.String("splunk-indexes", getEnv("SPLUNK_INDEXES", "honeynet,prod"), "Comma-separated list of Splunk indexes to query")

	// Responder
	flag.StringVar(&cfg.IPTablesChain, "iptables-chain", getEnv("IPTABLES_CHAIN", "INPUT"), "iptables chain for blocking")

	// Engine
	flag.DurationVar(&cfg.Tier2TTL, "tier2-ttl", getDurationEnv("TIER2_TTL", 10*time.Minute), "TTL for Tier 2 auto-unblock (e.g. 10m)")

	flag.Parse()

	// Post-process
	cfg.SplunkIndexes = strings.Split(*indexes, ",")
	for i := range cfg.SplunkIndexes {
		cfg.SplunkIndexes[i] = strings.TrimSpace(cfg.SplunkIndexes[i])
	}

	return cfg
}

// getEnv returns env var or fallback.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getDurationEnv parses duration env or returns fallback.
func getDurationEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return fallback
}
