// pkg/engine/engine.go
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"threat-central/pkg/models"
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
	CatchEvent() (*models.Alert, error)
}

// HistoryFetcher defines the interface for fetching related events from Splunk.
type HistoryFetcher interface {
	FetchHistory(ctx context.Context, srcIP string) ([]models.RawEvent, error)
}

// Engine processes incoming alerts.
type Engine struct {
	receiver   Receiver
	fetcher    HistoryFetcher
	responder  Responder
	tier2TTL   time.Duration
	SharedData *models.SharedData
	SigChannel chan struct{}
}

// NewEngine constructs the Engine.
func NewEngine(recv Receiver, fetch HistoryFetcher, resp Responder, ttl time.Duration) *Engine {
	return &Engine{receiver: recv, fetcher: fetch, responder: resp, tier2TTL: ttl,
		SharedData: &models.SharedData{
			IDSAlertsMap: make(map[string]*models.Alert),
			AlertsMap:    make(map[string]*models.Alert),
			AlertsList:   make([]*models.Alert, 0),
			SuricataList: make([]*models.Alert, 0),
			ModsecList:   make([]*models.Alert, 0),
			WazuhList:    make([]*models.Alert, 0),
		},
		SigChannel: make(chan struct{}, 0),
	}
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

		if value := e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, alert.Threat, alert.LogType)]; value == nil {
			e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, alert.Threat, alert.LogType)] = alert
			//e.alertsList = append(e.alertsList, alert)
		}

		a := e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, alert.Threat, alert.LogType)]
		if a.Suricata != nil {
			t := time.Now()
			if a.FirstTimestamp == nil {
				a.FirstTimestamp = &t
				e.SharedData.SuricataList = append(e.SharedData.SuricataList, a)
			} else {
				a.Suricata = append(a.Suricata, alert.Suricata...)
			}
			a.LastTimestamp = &t
			//sort
		} else if a.Modsec != nil {
			t := time.Now()
			if a.FirstTimestamp == nil {
				a.FirstTimestamp = &t
				e.SharedData.ModsecList = append(e.SharedData.ModsecList, a)
			} else {
				a.Modsec = append(a.Modsec, alert.Modsec...)
			}
			a.LastTimestamp = &t
			//sort
		} else {

			//e.wazuhList = append(e.wazuhList, alert)
		}

		if value := e.SharedData.AlertsMap[fmt.Sprintf("%s-%s", alert.IP, alert.DstPort)]; value == nil {
			e.SharedData.AlertsMap[fmt.Sprintf("%s-%s", alert.IP, alert.DstPort)] = alert
			//e.alertsList = append(e.alertsList, alert)
		}

		a = e.SharedData.AlertsMap[fmt.Sprintf("%s-%s", alert.IP, alert.DstPort)]
		t := time.Now()
		if a.FirstTimestamp == nil {
			a.FirstTimestamp = &t
			e.SharedData.AlertsList = append(e.SharedData.AlertsList, a)
		} else {
			a.Suricata = append(a.Suricata, alert.Suricata...)
			a.Modsec = append(a.Modsec, alert.Modsec...)
			a.Wazuh = append(a.Wazuh, alert.Wazuh...)
		}
		a.LastTimestamp = &t
		for _, l := range e.SharedData.AlertsList {
			fmt.Println(*l)
		}

		//go e.processEvent(ctx, alert)

		continue
	}
}

func (e *Engine) processEvent(ctx context.Context, ev *models.Alert) {
	ip := net.ParseIP(ev.IP)
	if ip == nil {
		return
	}

	if (ev.LogType == "modsec" && ev.Severity >= 4) || (ev.LogType == "suricata" && ev.Severity == 1) {
		ev.Tier = 2
	} else {
		ev.Tier = 1
	}

	/*
		go func(ev *models.Alert) {
			history, _ := e.fetcher.FetchHistory(ctx, ev.SourceIP)
			ev.History = history
			e.alerts[ev.SourceIP] = ev
		}(ev)
	*/

	fmt.Print("\033[2J")
	PrintAlerts(e.alertsList)
	Prompt()
}

// PrintAlerts displays current alerts and their block status.
func PrintAlerts(alerts []*models.Alert) {
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
