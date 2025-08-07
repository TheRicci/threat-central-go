package splunkfetch

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"threat-central/pkg/models"
	"time"
)

// HistoryFetcher defines the interface for fetching related events from Splunk.
type HistoryFetcher interface {
	FetchHistory(ctx context.Context, srcIP string) ([]models.RawEvent, error)
}

// SplunkFetcher implements HistoryFetcher using Splunk REST API.
type SplunkFetcher struct {
	URL     string
	Token   string
	Indexes []string
	client  *http.Client
}

// New creates a new SplunkFetcher with the given parameters.
func New(url, token string, indexes []string) HistoryFetcher {
	return &SplunkFetcher{
		URL:     url,
		Token:   token,
		Indexes: indexes,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchHistory queries Splunk REST API for all events from srcIP in given indexes.
// It creates a blocking search job, then fetches results in JSON.
func (sf *SplunkFetcher) FetchHistory(ctx context.Context, srcIP string) ([]models.RawEvent, error) {
	// Build the search string
	idxList := strings.Join(sf.Indexes, ",")
	search := fmt.Sprintf("search index IN (%s) src_ip=\"%s\" earliest=-24h latest=now | table _time, index, sourcetype, *", idxList, srcIP)

	// 1. Create search job
	data := url.Values{}
	data.Set("search", search)
	data.Set("exec_mode", "blocking")
	req, err := http.NewRequestWithContext(ctx, "POST", sf.URL+"/services/search/jobs", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sf.Token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := sf.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create search job: %s", resp.Status)
	}

	// Parse SID from XML response
	var sid string
	decoder := xml.NewDecoder(resp.Body)
	for {
		tok, _ := decoder.Token()
		if tok == nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "sid" {
			var s string
			decoder.DecodeElement(&s, &se)
			sid = s
			break
		}
	}
	if sid == "" {
		return nil, fmt.Errorf("search job SID not found")
	}

	// 2. Fetch results in JSON
	resURL := fmt.Sprintf("%s/services/search/jobs/%s/results?output_mode=json&count=0", sf.URL, sid)
	resReq, err := http.NewRequestWithContext(ctx, "GET", resURL, nil)
	if err != nil {
		return nil, err
	}
	resReq.Header.Set("Authorization", "Bearer "+sf.Token)

	resResp, err := sf.client.Do(resReq)
	if err != nil {
		return nil, err
	}
	defer resResp.Body.Close()
	if resResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch results: %s", resResp.Status)
	}

	var result struct {
		Results []map[string]interface{} `json:"results"`
	}
	if err := json.NewDecoder(resResp.Body).Decode(&result); err != nil {
		return nil, err
	}

	raw := make([]models.RawEvent, len(result.Results))
	for i, rec := range result.Results {
		raw[i] = rec
	}
	return raw, nil
}
