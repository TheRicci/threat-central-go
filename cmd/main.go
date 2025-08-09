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

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	SharedData = models.SharedData{
		AlertsList:   make([]*models.Alert, 0),
		SuricataList: make([]*models.Alert, 0),
		ModsecList:   make([]*models.Alert, 0),
		WazuhList:    make([]*models.Alert, 0),
		AlertsMap:    make(map[string]*models.Alert),
		IDSAlertsMap: make(map[string]*models.Alert),
	}
	SigChannel = make(chan struct{})
)

func Run() error {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize components
	recv := generic.NewLogReceiver()
	fetcher := splunkfetch.New(cfg.SplunkURL, cfg.SplunkToken, cfg.SplunkIndexes)
	responder := ipt.New(cfg.IPTablesChain)
	eng := engine.NewEngine(recv, fetcher, responder, cfg.Tier2TTL, &SharedData, &SigChannel)

	// Run engine
	ctx := context.Background()
	log.Printf("Starting engine (listening on :80)...")
	return eng.Run(ctx)
}

func (m model) Init() tea.Cmd {
	return awaitLog
}

func awaitLog() tea.Msg {
	select {
	case <-SigChannel:
		return struct{}{}
	}
}

func main() {
	tables := make([]table.Model, 0, 4)
	var ta table.Model

	for i := 1; i < 5; i++ {
		columns := []table.Column{
			{Title: "Date", Width: 14},
			{Title: "IP", Width: 20},
			{Title: "Threat", Width: 20},
			{Title: "Log Source", Width: 10},
			{Title: "Level", Width: 10},
		}

		v := reflect.ValueOf(SharedData)
		fieldValue := v.Field(i)
		alerts, _ := fieldValue.Interface().([]*models.Alert)

		rows := []table.Row{}
		/*
			rows := []table.Row{
				{"Yesterday", "192.168.0.222", "XSS", "Suricata", "2"},
				{"Yesterday", "192.168.0.222", "SQLI", "Suricata", "3"},
				{"Yesterday", "122.177.25.221", "XSS", "Suricata", "2"},
			}
		*/

		for _, alert := range alerts {
			rows = append(rows, table.Row{
				alert.LastTimestamp.Format("2006-01-02 15:04:05"),
				alert.IP,
				*alert.Threat,
				*alert.LogType,
				fmt.Sprintf("%d", *alert.Severity),
			})
		}

		t := table.New(
			table.WithColumns(columns),
			table.WithRows(rows),
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
		if i == 1 {
			ta = t
		}
		tables = append(tables, t)
	}

	go func() {
		if err := Run(); err != nil {
			log.Printf("ADC engine terminated: %v", err)
			os.Exit(1)
		}
	}()

	tabs := []string{"     Suricata     ", "      ModSec       ", "           Wazuh         ", " Events "}
	m := model{Tabs: tabs, tables: tables, table: ta}
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}

}

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

/*
	func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
		var cmd tea.Cmd
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc":
				if m.tables[m.activeTab].Focused() {
					m.tables[m.activeTab].Blur()
				} else {
					m.tables[m.activeTab].Focus()
				}
			case "q", "ctrl+c":
				return m, tea.Quit
			case "enter":
				return m, tea.Batch(
					tea.Printf("Let's go to %s!", m.tables[m.activeTab].SelectedRow()[1]),
				)
			}
		}
		m.tables[m.activeTab], cmd = m.tables[m.activeTab].Update(msg)
		return m, cmd
	}
*/
type model struct {
	Tabs      []string
	activeTab int
	table     table.Model
	tables    []table.Model
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "right", "l", "n", "tab":
			m.activeTab = min(m.activeTab+1, len(m.Tabs)-1)
			return m, nil
		case "left", "h", "p", "shift+tab":
			m.activeTab = max(m.activeTab-1, 0)
			return m, nil
		}
	}

	return m, nil
}

func tabBorderWithBottom(left, middle, right string) lipgloss.Border {
	border := lipgloss.RoundedBorder()
	border.BottomLeft = left
	border.Bottom = middle
	border.BottomRight = right
	return border
}

var (
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
			border.BottomLeft = "├"
		} else if isLast && isActive {
			border.BottomRight = "│"
		} else if isLast && !isActive {
			border.BottomRight = "┤"
		}
		style = style.Border(border)
		renderedTabs = append(renderedTabs, style.Render(t))
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	doc.WriteString(row)
	doc.WriteString("\n")
	doc.WriteString(baseStyle.Render(m.tables[m.activeTab].View()))
	return docStyle.Render(doc.String())
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
