package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"threat-central/pkg/model"
)

// SplunkHECReceiver listens for HEC posts.
type SplunkHECReceiver struct {
	Addr    string
	Token   string
	chAlert chan (model.AlertEvent)
	chErr   chan (error)
}

func NewSplunkHEC(addr, token string) *SplunkHECReceiver {
	return &SplunkHECReceiver{Addr: addr, Token: token, chAlert: make(chan model.AlertEvent), chErr: make(chan error)}
}

// Events starts HTTP server
func (r *SplunkHECReceiver) ServerStart(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/receive", func(w http.ResponseWriter, req *http.Request) {
		// Verify token header
		if req.Header.Get("Authorization") != "Bearer "+r.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		defer req.Body.Close()

		var ev model.AlertEvent
		if err := json.NewDecoder(req.Body).Decode(&ev); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			r.chErr <- err
			return
		}
		r.chAlert <- ev
	})

	srv := &http.Server{Addr: r.Addr, Handler: mux}
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

func (r *SplunkHECReceiver) CatchEvent() (*model.AlertEvent, error) {
	for {
		select {
		case ev := <-r.chAlert:
			return &ev, nil
		case err := <-r.chErr:
			return nil, err
		}
	}
}
