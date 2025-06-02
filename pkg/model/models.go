package model

import "time"

type Alert struct {
	IP             string
	DstPort        int
	Url            string
	Threat         string
	Severity       int
	FirstTimestamp *time.Time
	Tier           int
	LogType        string
	Quantity       int
	Suricata       []SuricataEveLog
	Modsec         []ModsecAuditLog
}

type AlertEvent struct {
	Timestamp    time.Time `json:"_time"`
	ID           string    `json:"_indextime"`
	Index        string    `json:"index"`
	Sourcetype   string    `json:"sourcetype"`
	SourceIP     string    `json:"source.ip"`
	ThreatName   string    `json:"threat.name"`
	SignatureID  int       `json:"threat.signature_id"`
	Severity     int       `json:"event.severity"`
	RawCategory  string    `json:"category,omitempty"`
	RawSignature string    `json:"signature,omitempty"`

	History   []RawEvent `json:"-"`
	IsBlocked bool       `json:"-"`
	Tier      int        `json:"-"`
}

// ModsecAuditLog represents a full ModSecurity audit record in JSON form.
type ModsecAuditLog struct {
	Transaction struct {
		ClientIP   string `json:"client_ip"`
		TimeStamp  string `json:"time_stamp"`
		ServerID   string `json:"server_id"`
		ClientPort int    `json:"client_port"`
		HostIP     string `json:"host_ip"`
		HostPort   int    `json:"host_port"`
		UniqueID   string `json:"unique_id"`
		Request    struct {
			Method      string            `json:"method"`
			HTTPVersion float64           `json:"http_version"`
			URI         string            `json:"uri"`
			Headers     map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			Body     string            `json:"body"`
			HTTPCode int               `json:"http_code"`
			Headers  map[string]string `json:"headers"`
		} `json:"response"`
		Producer struct {
			ModSecurity    string   `json:"modsecurity"`
			Connector      string   `json:"connector"`
			SecRulesEngine string   `json:"secrules_engine"`
			Components     []string `json:"components"`
		} `json:"producer"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				Match      string   `json:"match"`
				Reference  string   `json:"reference"`
				RuleID     string   `json:"ruleId"`
				File       string   `json:"file"`
				LineNumber string   `json:"lineNumber"`
				Data       string   `json:"data"`
				Severity   string   `json:"severity"`
				Ver        string   `json:"ver"`
				Rev        string   `json:"rev"`
				Tags       []string `json:"tags"`
				Maturity   string   `json:"maturity"`
				Accuracy   string   `json:"accuracy"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

// SuricataEveLog represents one line of Suricata’s EVE JSON.
type SuricataEveLog struct {
	Timestamp string `json:"timestamp"`
	FlowID    int64  `json:"flow_id"`
	InIface   string `json:"in_iface"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	PktSrc    string `json:"pkt_src"`
	TxID      int    `json:"tx_id"`
	Alert     struct {
		Action      string `json:"action"`
		Gid         int    `json:"gid"`
		SignatureID int    `json:"signature_id"`
		Rev         int    `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		Metadata    struct {
			AffectedProduct   []string `json:"affected_product"`
			AttackTarget      []string `json:"attack_target"`
			Confidence        []string `json:"confidence"`
			CreatedAt         []string `json:"created_at"`
			Deployment        []string `json:"deployment"`
			SignatureSeverity []string `json:"signature_severity"`
			Tag               []string `json:"tag"`
			UpdatedAt         []string `json:"updated_at"`
		} `json:"metadata"`
	} `json:"alert"`
	HTTP struct {
		Hostname        string `json:"hostname"`
		URL             string `json:"url"`
		HTTPUserAgent   string `json:"http_user_agent"`
		XFF             string `json:"xff"`
		HTTPContentType string `json:"http_content_type"`
		HTTPMethod      string `json:"http_method"`
		Protocol        string `json:"protocol"`
		Status          int    `json:"status"`
		Length          int    `json:"length"`
	} `json:"http"`
	AppProto  string `json:"app_proto"`
	Direction string `json:"direction"`
	Flow      struct {
		PktsToserver  int    `json:"pkts_toserver"`
		PktsToclient  int    `json:"pkts_toclient"`
		BytesToserver int    `json:"bytes_toserver"`
		BytesToclient int    `json:"bytes_toclient"`
		Start         string `json:"start"`
		SrcIP         string `json:"src_ip"`
		DestIP        string `json:"dest_ip"`
		SrcPort       int    `json:"src_port"`
		DestPort      int    `json:"dest_port"`
	} `json:"flow"`
}

// RawEvent holds arbitrary key/value pairs for fetched history records.
type RawEvent map[string]interface{}
