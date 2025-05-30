package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"threat-central/pkg/model"
	"time"
)

type LogReceiver struct {
	chAlert chan (model.Alert)
	chErr   chan (error)
}

func NewLogReceiver(addr, token string) *LogReceiver {
	return &LogReceiver{chAlert: make(chan model.Alert), chErr: make(chan error)}
}

// Events starts HTTP server
func (r *LogReceiver) ServerStart(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/receive", func(w http.ResponseWriter, req *http.Request) {
		logType := req.Header.Get("Log-Type")

		body, _ := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		var ev model.Alert
		switch logType {
		case "nginx-modsec":
			var m model.ModsecAuditLog
			if err := json.Unmarshal(body, &m); err != nil {
				r.chErr <- err
				return
			}
			i, _ := strconv.Atoi(m.Transaction.Messages[0].Details.Severity)
			t, err := time.Parse("Mon Jan 02 15:04:05 2006", m.Transaction.TimeStamp)
			if err != nil {
				r.chErr <- fmt.Errorf("failed to parse ModSecurity timestamp: %v", err)
				return
			}
			ev = model.Alert{
				IP:             m.Transaction.ClientIP,
				DstPort:        m.Transaction.HostPort,
				Url:            m.Transaction.Request.URI,
				Threat:         m.Transaction.Messages[0].Details.Match,
				Severity:       i,
				FirstTimestamp: &t,
				LogType:        "modsec",
				Quantity:       1,
				Modsec:         []model.ModsecAuditLog{m},
			}

			r.chAlert <- ev
		case "suricata":
			var s model.SuricataEveLog
			if err := json.Unmarshal(body, &s); err != nil {
				r.chErr <- err
				return
			}
			t, err := time.Parse("2006-01-02T15:04:05.000000-0700", s.Timestamp)
			if err != nil {
				r.chErr <- fmt.Errorf("failed to parse Suricata timestamp: %v", err)
			}
			ev = model.Alert{
				IP:             s.SrcIP,
				DstPort:        s.DestPort,
				Url:            s.HTTP.URL,
				Threat:         s.Alert.Signature,
				FirstTimestamp: &t,
				Severity:       s.Alert.Severity,
				LogType:        "suricata",
				Quantity:       1,
				Suricata:       []model.SuricataEveLog{s},
			}

			r.chAlert <- ev
		default:
			http.Error(w, "unknown log type", http.StatusBadRequest)
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

func (r *LogReceiver) CatchEvent() (*model.Alert, error) {
	for {
		select {
		case ev := <-r.chAlert:
			return &ev, nil
		case err := <-r.chErr:
			return nil, err
		}
	}
}
