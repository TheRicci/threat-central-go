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
	AlertsList   []serializableAlert          `json:"alerts_list"`
	SuricataList []serializableAlert          `json:"suricata_list"`
	ModsecList   []serializableAlert          `json:"modsec_list"`
	WazuhList    []serializableAlert          `json:"wazuh_list"`
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
		AlertsList:   []*models.Alert{},
		SuricataList: []*models.Alert{},
		ModsecList:   []*models.Alert{},
		WazuhList:    []*models.Alert{},
		IDSAlertsMap: map[string]*models.Alert{},
		AlertsMap:    map[string]*models.Alert{},
	}
}

func toSerializable(sd *models.SharedData) *serializableSharedData {
	if sd == nil {
		return &serializableSharedData{
			AlertsList: []serializableAlert{}, SuricataList: []serializableAlert{},
			ModsecList: []serializableAlert{}, WazuhList: []serializableAlert{},
			IDSAlertsMap: map[string]serializableAlert{}, AlertsMap: map[string]serializableAlert{},
		}
	}
	s := &serializableSharedData{
		AlertsList:   make([]serializableAlert, 0, len(sd.AlertsList)),
		SuricataList: make([]serializableAlert, 0, len(sd.SuricataList)),
		ModsecList:   make([]serializableAlert, 0, len(sd.ModsecList)),
		WazuhList:    make([]serializableAlert, 0, len(sd.WazuhList)),
		IDSAlertsMap: make(map[string]serializableAlert, len(sd.IDSAlertsMap)),
		AlertsMap:    make(map[string]serializableAlert, len(sd.AlertsMap)),
	}
	for _, a := range sd.AlertsList {
		s.AlertsList = append(s.AlertsList, toSerializableAlert(a))
	}
	for _, a := range sd.SuricataList {
		s.SuricataList = append(s.SuricataList, toSerializableAlert(a))
	}
	for _, a := range sd.ModsecList {
		s.ModsecList = append(s.ModsecList, toSerializableAlert(a))
	}
	for _, a := range sd.WazuhList {
		s.WazuhList = append(s.WazuhList, toSerializableAlert(a))
	}
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
	for _, sa := range s.AlertsList {
		out.AlertsList = append(out.AlertsList, fromSerializableAlert(sa))
	}
	for _, sa := range s.SuricataList {
		out.SuricataList = append(out.SuricataList, fromSerializableAlert(sa))
	}
	for _, sa := range s.ModsecList {
		out.ModsecList = append(out.ModsecList, fromSerializableAlert(sa))
	}
	for _, sa := range s.WazuhList {
		out.WazuhList = append(out.WazuhList, fromSerializableAlert(sa))
	}
	for k, v := range s.IDSAlertsMap {
		out.IDSAlertsMap[k] = fromSerializableAlert(v)
	}
	for k, v := range s.AlertsMap {
		out.AlertsMap[k] = fromSerializableAlert(v)
	}
	return out
}

func fromSerializableAlert(sa serializableAlert) *models.Alert {
	a := &models.Alert{IP: sa.IP, Quantity: sa.Quantity, Suricata: sa.Suricata, Modsec: sa.Modsec, Wazuh: sa.Wazuh}
	a.DstPort = new(int)
	*a.DstPort = sa.DstPort
	a.Url = new(string)
	*a.Url = sa.Url
	a.Threat = new(string)
	*a.Threat = sa.Threat
	a.Severity = new(int)
	*a.Severity = sa.Severity
	a.Tier = new(int)
	*a.Tier = sa.Tier
	a.LogType = new(string)
	*a.LogType = sa.LogType
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
		if os.IsNotExist(err) {
			return defaultSharedData(), nil
		}
		return nil, err
	}
	defer f.Close()

	var s serializableSharedData
	dec := json.NewDecoder(f)
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
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
