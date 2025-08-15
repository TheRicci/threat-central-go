package generic

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"threat-central/pkg/models"
	"time"
)

type LogReceiver struct {
	chAlert chan (models.Alert)
	chErr   chan (error)
}

func NewLogReceiver() *LogReceiver {
	return &LogReceiver{chAlert: make(chan models.Alert), chErr: make(chan error)}
}

// normalizeTierFromSuricata converts Suricata severities (1=high,2=medium,3=low)
// into unified tiers (1=low,2=medium,3=high).
func normalizeTierFromSuricata(severity int) int {
	switch {
	case severity <= 1:
		return 3
	case severity == 2:
		return 2
	default:
		return 1
	}
}

// normalizeTierFromModsec converts ModSecurity severities (commonly 0-5, where
// 5/4 are most severe) into unified tiers (1=low,2=medium,3=high).
func normalizeTierFromModsec(severityStr string) int {
	sev, err := strconv.Atoi(severityStr)
	if err != nil {
		return 1
	}
	switch {
	case sev >= 4:
		return 3
	case sev == 3:
		return 2
	default:
		return 1
	}
}

// normalizeTierFromWazuh converts Wazuh rule levels (0-15) into unified tiers
// (1=low,2=medium,3=high). Typical mapping: 0-3 low, 4-7 medium, 8-15 high.
func normalizeTierFromWazuh(level int) int {
	switch {
	case level >= 8:
		return 3
	case level >= 4:
		return 2
	default:
		return 1
	}
}

// Events starts HTTP server
func (r *LogReceiver) ServerStart(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logs", func(w http.ResponseWriter, req *http.Request) {
		logType := req.Header.Get("Log-Type")

		body, _ := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		var ev models.Alert
		switch logType {
		case "modsec":
			var list []models.ModsecAuditLog
			if err := json.Unmarshal(body, &list); err != nil {
				r.chErr <- err
				return
			}

			for _, m := range list {
				i, _ := strconv.Atoi(m.Transaction.Messages[0].Details.Severity)
				t, err := time.Parse("Mon Jan _2 15:04:05 2006", m.Transaction.TimeStamp)
				if err != nil {
					r.chErr <- fmt.Errorf("failed to parse ModSecurity timestamp: %v", err)
					return
				}
				ty := "modsec"
				tier := normalizeTierFromModsec(m.Transaction.Messages[0].Details.Severity)
				ev = models.Alert{
					IP:             m.Transaction.ClientIP,
					DstPort:        &m.Transaction.HostPort,
					Url:            &m.Transaction.Request.URI,
					Threat:         &m.Transaction.Messages[0].Details.Match,
					Severity:       &i,
					FirstTimestamp: &t,
					Tier:           &tier,
					LogType:        &ty,
					Quantity:       1,
					Modsec:         []models.ModsecAuditLog{m},
				}
				r.chAlert <- ev
			}
		case "suricata":
			var list []models.SuricataEveLog
			if err := json.Unmarshal(body, &list); err != nil {
				r.chErr <- err
				return
			}

			for _, s := range list {
				t, err := time.Parse("2006-01-02T15:04:05.000000-0700", s.Timestamp)
				if err != nil {
					r.chErr <- fmt.Errorf("failed to parse Suricata timestamp: %v", err)
				}
				ty := "suricata"
				tier := normalizeTierFromSuricata(s.Alert.Severity)
				ev = models.Alert{
					IP:             s.SrcIP,
					DstPort:        &s.DestPort,
					Url:            &s.HTTP.URL,
					Threat:         &s.Alert.Signature,
					FirstTimestamp: &t,
					Severity:       &s.Alert.Severity,
					Tier:           &tier,
					LogType:        &ty,
					Quantity:       1,
					Suricata:       []models.SuricataEveLog{s},
				}
				r.chAlert <- ev
			}
		case "wazuh":
			var list []models.WazuhLog
			if err := json.Unmarshal(body, &list); err != nil {
				r.chErr <- err
				return
			}

			for _, w := range list {
				// Parse timestamp; try RFC3339Nano then RFC3339
				var t time.Time
				if tt, err := time.Parse(time.RFC3339Nano, w.Timestamp); err == nil {
					t = tt
				} else if tt, err := time.Parse(time.RFC3339, w.Timestamp); err == nil {
					t = tt
				} else {
					t = time.Now()
				}
				severity := w.Rule.Level
				threat := w.Rule.Description
				typeStr := "wazuh"
				// Defaults for optional pointer fields
				dstPort := 0
				url := ""
				tier := normalizeTierFromWazuh(severity)
				ev = models.Alert{
					IP:             w.Agent.IP,
					DstPort:        &dstPort,
					Url:            &url,
					Threat:         &threat,
					Severity:       &severity,
					FirstTimestamp: &t,
					Tier:           &tier,
					LogType:        &typeStr,
					Quantity:       1,
					Wazuh:          []models.WazuhLog{w},
				}
				r.chAlert <- ev
			}
		default:
			http.Error(w, "unknown log type", http.StatusBadRequest)
			fmt.Println(logType)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	})

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			r.chErr <- err
			ctx.Done()
		}
	}()

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
		close(r.chAlert)
		close(r.chErr)
	}()
}

func (r *LogReceiver) CatchEvent() (*models.Alert, error) {
	for {
		select {
		case ev := <-r.chAlert:
			return &ev, nil
		case err := <-r.chErr:
			return nil, err
		}
	}
}
