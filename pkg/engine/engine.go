// pkg/engine/engine.go
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"threat-central/pkg/models"
	"threat-central/pkg/storage"
	"time"

	"github.com/charmbracelet/bubbles/table"
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
	SavePath   string
	Rows       *[][]table.Row
}

// NewEngine constructs the Engine.
func NewEngine(recv Receiver, fetch HistoryFetcher, resp Responder, ttl time.Duration, SharedData *models.SharedData, ch *chan struct{}, dataPath string, rows *[][]table.Row) *Engine {
	return &Engine{receiver: recv, fetcher: fetch, responder: resp, tier2TTL: ttl,
		SharedData: SharedData,
		SigChannel: *ch,
		SavePath:   dataPath,
		Rows:       rows,
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

		if value := e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, *alert.Threat, *alert.LogType)]; value == nil {
			e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, *alert.Threat, *alert.LogType)] = alert
			//e.alertsList = append(e.alertsList, alert)
		}

		a := e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, *alert.Threat, *alert.LogType)]
		if a.Suricata != nil {
			t := time.Now()
			if a.FirstTimestamp == nil {
				a.FirstTimestamp = &t
				e.SharedData.SuricataList = append(e.SharedData.SuricataList, a)
			} else {
				a.Suricata = append(a.Suricata, alert.Suricata...)
			}
			a.LastTimestamp = &t
			sortAlertsByTimestamp(e.SharedData.SuricataList)
			addRows(&(*e.Rows)[0], &e.SharedData.SuricataList)
		} else if a.Modsec != nil {
			t := time.Now()
			if a.FirstTimestamp == nil {
				a.FirstTimestamp = &t
				e.SharedData.ModsecList = append(e.SharedData.ModsecList, a)
			} else {
				a.Modsec = append(a.Modsec, alert.Modsec...)
			}
			a.LastTimestamp = &t
			sortAlertsByTimestamp(e.SharedData.ModsecList)
			addRows(&(*e.Rows)[1], &e.SharedData.ModsecList)
		} else if a.Wazuh != nil {
			t := time.Now()
			if a.FirstTimestamp == nil {
				a.FirstTimestamp = &t
				e.SharedData.WazuhList = append(e.SharedData.WazuhList, a)
			} else {
				a.Wazuh = append(a.Wazuh, alert.Wazuh...)
			}
			a.LastTimestamp = &t
			sortAlertsByTimestamp(e.SharedData.WazuhList)
			addRows(&(*e.Rows)[2], &e.SharedData.WazuhList)
		}
		if value := e.SharedData.AlertsMap[fmt.Sprintf("%s-%d", alert.IP, alert.DstPort)]; value == nil {
			e.SharedData.AlertsMap[fmt.Sprintf("%s-%d", alert.IP, alert.DstPort)] = alert
			//e.alertsList = append(e.alertsList, alert)
		}

		a = e.SharedData.AlertsMap[fmt.Sprintf("%s-%d", alert.IP, alert.DstPort)]
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
		sortAlertsByTimestamp(e.SharedData.AlertsList)
		addRows(&(*e.Rows)[3], &e.SharedData.AlertsList)
		/*
			for _, l := range e.SharedData.AlertsList {
				fmt.Println(*l)
			}
		*/

		// Persist updated state; log error but continue
		if err := storage.SaveSharedData(e.SavePath, e.SharedData); err != nil {
			log.Printf("failed to save shared data: %v", err)
		}

		e.SigChannel <- struct{}{}

		continue
	}
}

func addRows(rows *[]table.Row, alert *[]*models.Alert) {
	*rows = make([]table.Row, 0)
	for _, a := range *alert {
		*rows = append(*rows, table.Row{
			a.LastTimestamp.Format("2006-01-02 15:04:05"),
			a.IP,
			*a.Threat,
			*a.LogType,
			fmt.Sprintf("%d", *a.Severity),
		})
	}
}

func sortAlertsByTimestamp(alerts []*models.Alert) {
	sort.Slice(alerts, func(i, j int) bool {
		// Handle nil timestamps by sorting them to the end.
		if alerts[j].LastTimestamp == nil {
			return true // j is nil, so i should come first.
		}
		if alerts[i].LastTimestamp == nil {
			return false // i is nil, so j should come first.
		}
		// Sort in descending order (most recent first).
		return alerts[i].LastTimestamp.After(*alerts[j].LastTimestamp)
	})
}

/*
func (e *Engine) processEvent(ctx context.Context, ev *models.Alert) {

		go func(ev *models.Alert) {
			history, _ := e.fetcher.FetchHistory(ctx, ev.SourceIP)
			ev.History = history
			e.alerts[ev.SourceIP] = ev
		}(ev)


}*/
