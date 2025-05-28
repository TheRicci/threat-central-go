package model

import "time"

// AlertEvent represents a CIM-normalized alert event from Splunk HEC
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

// RawEvent holds arbitrary key/value pairs for fetched history records.
type RawEvent map[string]interface{}
