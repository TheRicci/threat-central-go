// pkg/engine/engine.go
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
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

		value := e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, *alert.Threat, *alert.LogType)]
		if value == nil {
			e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, *alert.Threat, *alert.LogType)] = alert
		}

		a := e.SharedData.IDSAlertsMap[fmt.Sprintf("%s-%s-%s", alert.IP, *alert.Threat, *alert.LogType)]
		a.LastTimestamp = alert.FirstTimestamp
		if a.Suricata != nil {
			if value == nil {
				e.SharedData.SuricataList = append(e.SharedData.SuricataList, a)
			} else {
				//quatity
				//a.LastTimestamp = alert.FirstTimestamp
				a.Suricata = append(a.Suricata, alert.Suricata...)
			}
			sortAlertsByTimestamp(e.SharedData.SuricataList)
			//fmt.Println(e.SharedData.SuricataList)
			//fmt.Println(&(*e.Rows)[0])
			//fmt.Println(len((*e.Rows)[0]))
			AddRows(&(*e.Rows)[0], &e.SharedData.SuricataList)
		} else if a.Modsec != nil {
			if value == nil {
				e.SharedData.ModsecList = append(e.SharedData.ModsecList, a)
			} else {
				//		a.LastTimestamp = alert.FirstTimestamp
				a.Modsec = append(a.Modsec, alert.Modsec...)
			}
			sortAlertsByTimestamp(e.SharedData.ModsecList)
			AddRows(&(*e.Rows)[1], &e.SharedData.ModsecList)
		} else if a.Wazuh != nil {
			if value == nil {
				e.SharedData.WazuhList = append(e.SharedData.WazuhList, a)
			} else {
				//			a.LastTimestamp = alert.FirstTimestamp
				a.Wazuh = append(a.Wazuh, alert.Wazuh...)
			}
			sortAlertsByTimestamp(e.SharedData.WazuhList)
			AddRows(&(*e.Rows)[2], &e.SharedData.WazuhList)
		}
		value = e.SharedData.AlertsMap[fmt.Sprintf("%s-%d", alert.IP, *alert.DstPort)]
		if value == nil {
			temp := *alert
			alert = &temp
			e.SharedData.AlertsMap[fmt.Sprintf("%s-%d", alert.IP, *alert.DstPort)] = alert
		}

		a = e.SharedData.AlertsMap[fmt.Sprintf("%s-%d", alert.IP, *alert.DstPort)]
		//fmt.Println(a)
		a.LastTimestamp = alert.FirstTimestamp
		if value == nil {
			e.SharedData.AlertsList = append(e.SharedData.AlertsList, a)
		} else {
			//a.LastTimestamp = alert.FirstTimestamp
			a.Suricata = append(a.Suricata, alert.Suricata...)
			a.Modsec = append(a.Modsec, alert.Modsec...)
			a.Wazuh = append(a.Wazuh, alert.Wazuh...)
		}
		sortAlertsByTimestamp(e.SharedData.AlertsList)
		AddRows(&(*e.Rows)[3], &e.SharedData.AlertsList)

		go func() {
			//fmt.Println(*e.SharedData)
			if err := storage.SaveSharedData(e.SavePath, e.SharedData); err != nil {
				log.Printf("failed to save shared data: %v", err)
			}
		}()

		//fmt.Println("addrows", *e.Rows)
		e.SigChannel <- struct{}{}

		continue
	}
}

func AddRows(rows *[]table.Row, alerts *[]*models.Alert) {
	aSlice := *alerts
	r := make([]table.Row, 0, len(aSlice))

	for _, a := range aSlice {
		if a == nil {
			continue
		}

		threat := ""
		if a.Threat != nil {
			threat = *a.Threat
		}

		logType := ""
		if a.LogType != nil {
			logType = *a.LogType
		}

		severity := ""
		if a.Severity != nil {
			severity = strconv.Itoa(*a.Severity)
		}
		/*
			ts := ""
			if !a.LastTimestamp.IsZero() {
				ts = a.LastTimestamp.Format("2006-01-02 15:04:05")
			}
		*/
		r = append(r, table.Row{
			a.LastTimestamp.String(),
			a.IP,
			threat,
			logType,
			severity,
		})
	}
	//fmt.Println("addrows", r)
	*rows = r

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
