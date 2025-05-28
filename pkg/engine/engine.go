// pkg/engine/engine.go
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"threat-central/pkg/model"
	"time"
)

// Responder executes block/watch actions.
type Responder interface {
	Block(ctx context.Context, ip net.IP) error
	Unblock(ctx context.Context, ip net.IP) error
}

// Receiver receives AlertEvents from Splunk HEC or REST.
type Receiver interface {
	ServerStart(ctx context.Context)
	CatchEvent() (*model.AlertEvent, error)
}

// HistoryFetcher defines the interface for fetching related events from Splunk.
type HistoryFetcher interface {
	FetchHistory(ctx context.Context, srcIP string) ([]model.RawEvent, error)
}

// Engine processes incoming alerts.
type Engine struct {
	receiver  Receiver
	fetcher   HistoryFetcher
	responder Responder
	tier2TTL  time.Duration
	alerts    map[string]*[]model.AlertEvent
}

// NewEngine constructs the Engine.
func NewEngine(recv Receiver, fetch HistoryFetcher, resp Responder, ttl time.Duration) *Engine {
	return &Engine{receiver: recv, fetcher: fetch, responder: resp, tier2TTL: ttl}
}

// Run starts the main loop.
func (e *Engine) Run(ctx context.Context) error {
	e.receiver.ServerStart(ctx)
	for {
		alert, err := e.receiver.CatchEvent()
		if err != nil {
			log.Printf("[!] Error while awating for event: %s", err)
			continue
		}
		e.alerts[alert.SourceIP] = alert
		e.processEvent(ctx, alert)
		continue
	}
}

func (e *Engine) processEvent(ctx context.Context, ev *model.AlertEvent) {
	ip := net.ParseIP(ev.SourceIP)
	if ip == nil {
		return
	}

	ev.Tier = 1
	if ev.Severity >= 3 {
		ev.Tier = 2
		e.responder.Block(ctx, ip)
		go e.autoUnblock(ctx, ip)
	}

	go func(ev *model.AlertEvent) {
		history, _ := e.fetcher.FetchHistory(ctx, ev.SourceIP)
		ev.History = history
		e.alerts[ev.SourceIP] = ev
	}(ev)

	fmt.Print("\033[2J")
	PrintAlerts(e.alerts)
	Prompt()
}

func (e *Engine) autoUnblock(ctx context.Context, ip net.IP) {
	time.Sleep(e.tier2TTL)
	e.responder.Unblock(ctx, ip)
}

// PrintAlerts displays current alerts and their block status.
func PrintAlerts(alerts map[string]*model.AlertEvent) {
	// Gather keys and sort for consistent ordering
	ips := make([]string, 0, len(alerts))
	for ip := range alerts {
		ips = append(ips, ip)
	}

	// Header
	fmt.Printf("%-15s  %-4s  %-7s  %s\n", "IP", "Tier", "Blocked", "Since")
	fmt.Println("---------------------------------------------------")

	now := time.Now()
	for _, ip := range ips {
		ev := alerts[ip]
		tier := ev.Tier
		blocked := "No"
		if tier == 2 {
			blocked = "Yes"
		}
		since := now.Sub(ev.Timestamp).Round(time.Second)
		fmt.Printf("%-15s  %-4d  %-7s  %s ago\n", ev.SourceIP, tier, blocked, since)
	}
}

// Prompt prints the interactive prompt for user commands.
func Prompt() {
	fmt.Print("\nCommand> ")
}
