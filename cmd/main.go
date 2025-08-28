package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"threat-central/pkg/config"
	"threat-central/pkg/engine"
	splunkfetch "threat-central/pkg/fetcher/splunk"
	"threat-central/pkg/models"
	"threat-central/pkg/receiver/generic"
	ipt "threat-central/pkg/responder/iptables"
	"threat-central/pkg/storage"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

var (
	SharedData models.SharedData
	rows       *[][]table.Row
	SigChannel = make(chan struct{})
)

const dataFilePath = "shared_data.json"

func Run() error {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize components
	recv := generic.NewLogReceiver()
	fetcher := splunkfetch.New(cfg.SplunkURL, cfg.SplunkToken, cfg.SplunkIndexes)
	responder := ipt.New(cfg.IPTablesChain)
	eng := engine.NewEngine(recv, fetcher, responder, cfg.Tier2TTL, &SharedData, &SigChannel, dataFilePath, rows)

	// Run engine
	ctx := context.Background()
	log.Printf("Starting engine (listening on :80)...")
	return eng.Run(ctx)
}

func (m model) Init() tea.Cmd {
	return awaitLog
}

func awaitLog() tea.Msg {
	<-SigChannel
	return struct{}{}
}

func main() {
	// Load persisted data at startup
	loaded, err := storage.LoadSharedData(dataFilePath)
	if err != nil {
		log.Printf("failed to load shared data: %v", err)
		SharedData = models.SharedData{
			AlertsList:   make([]*models.Alert, 0),
			SuricataList: make([]*models.Alert, 0),
			ModsecList:   make([]*models.Alert, 0),
			WazuhList:    make([]*models.Alert, 0),
			AlertsMap:    make(map[string]*models.Alert),
			IDSAlertsMap: make(map[string]*models.Alert),
		}
	} else {
		SharedData = *loaded
	}

	tables := make([]table.Model, 0, 4)
	r := make([][]table.Row, 4)
	rows = &r
	for i := 0; i < 4; i++ {
		columns := []table.Column{}
		if i == 3 {
			columns = []table.Column{
				{Title: "Last", Width: 17},
				{Title: "IP", Width: 30},
				{Title: "Port", Width: 9},
				{Title: "Level", Width: 9},
				{Title: "Count", Width: 9},
			}
		} else {
			columns = []table.Column{
				{Title: "Last", Width: 16},
				{Title: "IP", Width: 16},
				{Title: "Threat", Width: 28},
				{Title: "Severity", Width: 8},
				{Title: "Count", Width: 6},
			}
		}

		// Initialize each slice in the rows array
		(*rows)[i] = make([]table.Row, 0)

		// Populate with existing data if available
		v := reflect.ValueOf(SharedData)
		fieldValue := v.Field(i)
		alerts, _ := fieldValue.Interface().([]*models.Alert)
		if len(alerts) > 0 {
			engine.AddRows(&(*rows)[i], &alerts)
		}
		/*
			v := reflect.ValueOf(SharedData)
			fieldValue := v.Field(i)

			alerts, _ := fieldValue.Interface().([]*models.Alert)

			rows := []table.Row{}

			for _, alert := range alerts {
				rows = append(rows, table.Row{
					alert.LastTimestamp.Format("2006-01-02 15:04:05"),
					alert.IP,
					*alert.Threat,
					*alert.LogType,
					fmt.Sprintf("%d", *alert.Severity),
				})
			}
		*/
		t := table.New(
			table.WithColumns(columns),
			table.WithFocused(true),
			table.WithHeight(7),
		)

		s := table.DefaultStyles()
		s.Header = s.Header.
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			BorderBottom(true).
			Bold(false)
		s.Selected = s.Selected.
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Bold(false)
		t.SetStyles(s)

		tables = append(tables, t)
	}

	go func() {
		if err := Run(); err != nil {
			log.Printf("ADC engine terminated: %v", err)
			os.Exit(1)
		}
	}()

	const width = 78
	vp := viewport.New(width, 20)
	vp.Style = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		PaddingRight(2)

	tables[0].SetRows((*rows)[0])
	tabs := []string{"     Suricata     ", "      ModSec       ", "           Wazuh         ", " Events "}
	m := model{Tabs: tabs, tables: tables, viewport: vp}
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}

}

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type model struct {
	Tabs      []string
	activeTab int
	tables    []table.Model
	openAlert *models.Alert
	viewport  viewport.Model
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case struct{}:
		m.tables[m.activeTab].SetRows((*rows)[m.activeTab])
		return m, awaitLog
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "right", "l", "n", "tab":
			m.activeTab = min(m.activeTab+1, len(m.Tabs)-1)
			m.tables[m.activeTab].SetRows((*rows)[m.activeTab])
			return m, nil
		case "left", "h", "p", "shift+tab":
			m.activeTab = max(m.activeTab-1, 0)
			m.tables[m.activeTab].SetRows((*rows)[m.activeTab])
			return m, nil
		case "r":
			m.openAlert = nil
			return m, nil
		case "enter":
			v := reflect.ValueOf(SharedData)
			fieldValue := v.Field(m.activeTab)
			alerts, _ := fieldValue.Interface().([]*models.Alert)
			m.openAlert = alerts[m.tables[m.activeTab].Cursor()]
			//fmt.Println(m.tables[m.activeTab].Cursor())
			//fmt.Println(*m.openAlert)
			return m, nil
		}
	}
	m.tables[m.activeTab], cmd = m.tables[m.activeTab].Update(msg)
	return m, cmd
}

func tabBorderWithBottom(left, middle, right string) lipgloss.Border {
	border := lipgloss.RoundedBorder()
	border.BottomLeft = left
	border.Bottom = middle
	border.BottomRight = right
	return border
}

var (
	helpStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render
	inactiveTabBorder = tabBorderWithBottom("┴", "─", "┴")
	activeTabBorder   = tabBorderWithBottom("┘", " ", "└")
	docStyle          = lipgloss.NewStyle().Padding(1, 2, 1, 2)
	highlightColor    = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	inactiveTabStyle  = lipgloss.NewStyle().Border(inactiveTabBorder, true).BorderForeground(highlightColor).Padding(0, 1)
	activeTabStyle    = inactiveTabStyle.Border(activeTabBorder, true)
	windowStyle       = lipgloss.NewStyle().BorderForeground(highlightColor).Padding(2, 0).Align(lipgloss.Center).Border(lipgloss.NormalBorder()).UnsetBorderTop()
)

func (m model) View() string {
	doc := strings.Builder{}
	if m.openAlert != nil {
		const glamourGutter = 2
		const width = 78
		glamourRenderWidth := width - m.viewport.Style.GetHorizontalFrameSize() - glamourGutter

		renderer, err := glamour.NewTermRenderer(
			glamour.WithAutoStyle(),
			glamour.WithWordWrap(glamourRenderWidth),
		)
		if err != nil {
			return ""
		}

		str, err := renderer.Render(
			fmt.Sprintf(`
# 🚨 Alert

| Field          | Value |
|----------------|-------|
| **IP**         | %s |
| **Dst Port**   | %v |
| **URL**        | %v |
| **Threat**     | %v |
| **Severity**   | %v |
| **Tier**       | %v |
| **Log Type**   | %v |
| **Quantity**   | %d |
| **First** | %s |
| **Last**  | %s |

---
`, m.openAlert.IP,
				*m.openAlert.DstPort,
				*m.openAlert.Url,
				*m.openAlert.Threat,
				*m.openAlert.Severity,
				*m.openAlert.Tier,
				*m.openAlert.LogType,
				m.openAlert.Quantity,
				m.openAlert.FirstTimestamp.Format("2006-01-02 15:04:05"),
				m.openAlert.LastTimestamp.Format("2006-01-02 15:04:05"),
			),
		)
		if err != nil {
			return ""
		}

		m.viewport.SetContent(str)
		return m.viewport.View() + helpStyle("\n  ↑/↓: Navigate • r: Return • q: Quit\n")
		/*
			doc.WriteString(baseStyle.Render(m.openAlert.IP))
			doc.WriteString("\n")
			doc.WriteString(baseStyle.Render(*m.openAlert.Threat))
			doc.WriteString("\n")
			doc.WriteString(baseStyle.Render(*m.openAlert.LogType))
		*/
	}

	var renderedTabs []string

	for i, t := range m.Tabs {
		var style lipgloss.Style
		isFirst, isLast, isActive := i == 0, i == len(m.Tabs)-1, i == m.activeTab
		if isActive {
			style = activeTabStyle
		} else {
			style = inactiveTabStyle
		}
		border, _, _, _, _ := style.GetBorder()
		if isFirst && isActive {
			border.BottomLeft = "│"
		} else if isFirst && !isActive {
			border.BottomLeft = "└"
		} else if isLast && isActive {
			border.BottomRight = "│"
		} else if isLast && !isActive {
			border.BottomRight = "┘"
		}
		style = style.Border(border)
		renderedTabs = append(renderedTabs, style.Render(t))
	}

	t := m.tables[m.activeTab]

	row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	doc.WriteString(row)
	doc.WriteString("\n")
	doc.WriteString(baseStyle.Render(t.View()))
	return docStyle.Render(doc.String()) + helpStyle("\n  ↑/↓: Navigate • ←/→: Switch Tab • Enter: Open Alert • q: Quit\n")
	//return baseStyle.Render(m.tables[m.activeTab].View()) + "\n"
	//return baseStyle.Render(m.table.View()) + "\n"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
