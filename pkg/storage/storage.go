package storage

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"threat-central/pkg/models"
	"time"
)

// Minimal DTOs to persist values (no pointers) for portability
type serializableSharedData struct {
	IDSAlertsMap map[string]serializableAlert `json:"ids_alerts_map"`
	AlertsMap    map[string]serializableAlert `json:"alerts_map"`
}

type serializableAlert struct {
	IP             string                  `json:"ip"`
	DstPort        int                     `json:"dst_port"`
	Url            string                  `json:"url"`
	Threat         string                  `json:"threat"`
	Severity       int                     `json:"severity"`
	FirstTimestamp string                  `json:"first_timestamp"`
	LastTimestamp  string                  `json:"last_timestamp"`
	Tier           int                     `json:"tier"`
	LogType        string                  `json:"log_type"`
	Quantity       int                     `json:"quantity"`
	Suricata       []models.SuricataEveLog `json:"suricata"`
	Modsec         []models.ModsecAuditLog `json:"modsec"`
	Wazuh          []models.WazuhLog       `json:"wazuh"`
}

func defaultSharedData() *models.SharedData {
	return &models.SharedData{
		SuricataList: []*models.Alert{},
		ModsecList:   []*models.Alert{},
		WazuhList:    []*models.Alert{},
		AlertsList:   []*models.Alert{},
		IDSAlertsMap: map[string]*models.Alert{},
		AlertsMap:    map[string]*models.Alert{},
	}
}

func toSerializable(sd *models.SharedData) *serializableSharedData {
	if sd == nil {
		return &serializableSharedData{
			IDSAlertsMap: map[string]serializableAlert{}, AlertsMap: map[string]serializableAlert{},
		}
	}

	s := &serializableSharedData{
		IDSAlertsMap: make(map[string]serializableAlert, len(sd.IDSAlertsMap)),
		AlertsMap:    make(map[string]serializableAlert, len(sd.AlertsMap)),
	}

	// copy maps -> map fields (always)
	for k, v := range sd.IDSAlertsMap {
		s.IDSAlertsMap[k] = toSerializableAlert(v)
	}
	for k, v := range sd.AlertsMap {
		s.AlertsMap[k] = toSerializableAlert(v)
	}

	return s
}

func toSerializableAlert(a *models.Alert) serializableAlert {
	if a == nil {
		return serializableAlert{}
	}
	sa := serializableAlert{IP: a.IP, Quantity: a.Quantity, Suricata: a.Suricata, Modsec: a.Modsec, Wazuh: a.Wazuh}
	if a.DstPort != nil {
		sa.DstPort = *a.DstPort
	}
	if a.Url != nil {
		sa.Url = *a.Url
	}
	if a.Threat != nil {
		sa.Threat = *a.Threat
	}
	if a.Severity != nil {
		sa.Severity = *a.Severity
	}
	if a.Tier != nil {
		sa.Tier = *a.Tier
	}
	if a.LogType != nil {
		sa.LogType = *a.LogType
	}
	if a.FirstTimestamp != nil {
		sa.FirstTimestamp = a.FirstTimestamp.UTC().Format(time.RFC3339Nano)
	}
	if a.LastTimestamp != nil {
		sa.LastTimestamp = a.LastTimestamp.UTC().Format(time.RFC3339Nano)
	}
	return sa
}

func fromSerializable(s *serializableSharedData) *models.SharedData {
	if s == nil {
		return defaultSharedData()
	}
	out := defaultSharedData()

	for k, v := range s.IDSAlertsMap {
		alert := fromSerializableAlert(v)
		out.IDSAlertsMap[k] = alert
		switch *alert.LogType {
		case "suricata", "Suricata":
			out.SuricataList = append(out.SuricataList, alert)
		case "modsec", "Modsec":
			out.ModsecList = append(out.ModsecList, alert)
		case "wazuh", "Wazuh":
			out.WazuhList = append(out.WazuhList, alert)
		}
	}
	for k, v := range s.AlertsMap {
		alert := fromSerializableAlert(v)
		out.AlertsMap[k] = alert
		out.AlertsList = append(out.AlertsList, alert)
	}
	return out
}

func fromSerializableAlert(sa serializableAlert) *models.Alert {
	a := &models.Alert{IP: sa.IP, Quantity: sa.Quantity, Suricata: sa.Suricata, Modsec: sa.Modsec, Wazuh: sa.Wazuh}

	if sa.DstPort != 0 {
		a.DstPort = new(int)
		*a.DstPort = sa.DstPort
	}
	if sa.Url != "" {
		a.Url = new(string)
		*a.Url = sa.Url
	}
	if sa.Threat != "" {
		a.Threat = new(string)
		*a.Threat = sa.Threat
	}
	// severity/tier: if your domain treats zero as valid you may want to leave this as-is,
	// otherwise only set when non-zero:
	if sa.Severity != 0 {
		a.Severity = new(int)
		*a.Severity = sa.Severity
	}
	if sa.Tier != 0 {
		a.Tier = new(int)
		*a.Tier = sa.Tier
	}
	if sa.LogType != "" {
		a.LogType = new(string)
		*a.LogType = sa.LogType
	}
	if sa.FirstTimestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, sa.FirstTimestamp); err == nil {
			a.FirstTimestamp = &t
		}
	}
	if sa.LastTimestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, sa.LastTimestamp); err == nil {
			a.LastTimestamp = &t
		}
	}
	return a
}

// LoadSharedData reads SharedData from the given JSON file.
// If the file does not exist, it returns an initialized empty structure.
func LoadSharedData(path string) (*models.SharedData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var s serializableSharedData
	dec := json.NewDecoder(f)
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	//fmt.Println("serializableSharedData", s)
	//fmt.Println("fromSerializable", fromSerializable(&s))
	return fromSerializable(&s), nil
}

// SaveSharedData atomically writes SharedData to the given JSON file.
func SaveSharedData(path string, data *models.SharedData) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(toSerializable(data)); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// On Windows, rename over existing file can fail; remove target first if it exists
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
	return os.Rename(tmp, path)
}
