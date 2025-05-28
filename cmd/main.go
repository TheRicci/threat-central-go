package main

import (
	"context"
	"log"
	"os"
	"threat-central/pkg/config"
	"threat-central/pkg/engine"
	splunkfetch "threat-central/pkg/fetcher/splunk"
	"threat-central/pkg/receiver/splunk"
	ipt "threat-central/pkg/responder/iptables"
)

func Run() error {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize components
	recv := splunk.NewSplunkHEC(cfg.HECAddr, cfg.HECToken)
	fetcher := splunkfetch.New(cfg.SplunkURL, cfg.SplunkToken, cfg.SplunkIndexes)
	responder := ipt.New(cfg.IPTablesChain)
	eng := engine.NewEngine(recv, fetcher, responder, cfg.Tier2TTL)

	// Run engine
	ctx := context.Background()
	log.Printf("Starting ADC engine (HEC listening on %s)...", cfg.HECAddr)
	return eng.Run(ctx)
}

func main() {
	if err := Run(); err != nil {
		log.Printf("ADC engine terminated: %v", err)
		os.Exit(1)
	}
}
