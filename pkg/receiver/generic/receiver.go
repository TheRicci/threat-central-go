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
				ev = models.Alert{
					IP:             m.Transaction.ClientIP,
					DstPort:        &m.Transaction.HostPort,
					Url:            &m.Transaction.Request.URI,
					Threat:         &m.Transaction.Messages[0].Details.Match,
					Severity:       &i,
					FirstTimestamp: &t,
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
				ev = models.Alert{
					IP:             s.SrcIP,
					DstPort:        &s.DestPort,
					Url:            &s.HTTP.URL,
					Threat:         &s.Alert.Signature,
					FirstTimestamp: &t,
					Severity:       &s.Alert.Severity,
					LogType:        &ty,
					Quantity:       1,
					Suricata:       []models.SuricataEveLog{s},
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
