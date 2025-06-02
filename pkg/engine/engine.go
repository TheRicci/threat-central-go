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
	CatchEvent() (*model.Alert, error)
}

// HistoryFetcher defines the interface for fetching related events from Splunk.
type HistoryFetcher interface {
	FetchHistory(ctx context.Context, srcIP string) ([]model.RawEvent, error)
}

// Engine processes incoming alerts.
type Engine struct {
	receiver   Receiver
	fetcher    HistoryFetcher
	responder  Responder
	tier2TTL   time.Duration
	alertsList []*model.Alert
	alertsMap  map[string]*model.Alert
}

// NewEngine constructs the Engine.
func NewEngine(recv Receiver, fetch HistoryFetcher, resp Responder, ttl time.Duration) *Engine {
	return &Engine{receiver: recv, fetcher: fetch, responder: resp, tier2TTL: ttl, alertsList: make([]*model.Alert, 0), alertsMap: make(map[string]*model.Alert)}
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

		if value := e.alertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, alert.Threat, alert.LogType)]; value == nil {
			e.alertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, alert.Threat, alert.LogType)] = alert
			e.alertsList = append(e.alertsList, alert)
		} else {
			a := e.alertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, alert.Threat, alert.LogType)]
			if a.Suricata != nil {
				a.Suricata = append(a.Suricata, alert.Suricata...)
			} else {
				a.Modsec = append(a.Modsec, alert.Modsec...)
			}
		}

		for _, l := range e.alertsList {
			fmt.Println(*l)
		}

		//go e.processEvent(ctx, alert)

		continue
	}
}

func (e *Engine) processEvent(ctx context.Context, ev *model.Alert) {
	ip := net.ParseIP(ev.IP)
	if ip == nil {
		return
	}

	if (ev.LogType == "modsec" && ev.Severity >= 4) || (ev.LogType == "suricata" && ev.Severity == 1) {
		ev.Tier = 2
		e.responder.Block(ctx, ip)
		go e.autoUnblock(ctx, ip)
	} else {
		ev.Tier = 1
	}

	/*
		go func(ev *model.Alert) {
			history, _ := e.fetcher.FetchHistory(ctx, ev.SourceIP)
			ev.History = history
			e.alerts[ev.SourceIP] = ev
		}(ev)
	*/

	fmt.Print("\033[2J")
	PrintAlerts(e.alertsList)
	Prompt()
}

func (e *Engine) autoUnblock(ctx context.Context, ip net.IP) {
	time.Sleep(e.tier2TTL)
	e.responder.Unblock(ctx, ip)
}

// PrintAlerts displays current alerts and their block status.
func PrintAlerts(alerts []*model.Alert) {
	// Header
	fmt.Printf("%-15s  %-4s  %-7s  %s\n", "IP", "Tier", "Blocked", "Since")
	fmt.Println("---------------------------------------------------")

	now := time.Now()
	for _, a := range alerts {
		tier := a.Tier
		blocked := "No"
		if a.Tier == 2 {
			blocked = "Yes"
		}
		since := now.Sub(*a.FirstTimestamp).Round(time.Second)
		fmt.Printf("%-15s  %-4d  %-7s first: %s \n", a.IP, tier, blocked, since)
	}
}

// Prompt prints the interactive prompt for user commands.
func Prompt() {
	fmt.Print("\nCommand> ")
}
