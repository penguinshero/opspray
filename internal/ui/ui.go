package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/penguinshero/opspray/internal/scanner"
)

// RenderResults displays target metadata and scan results in a clean terminal layout.
func RenderResults(targetIP, domain, username string, results []scanner.PortResult) {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	labelStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	portStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	validStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	fmt.Println(headerStyle.Render("opspray scan summary"))
	fmt.Printf("%s %s\n", labelStyle.Render("Target:"), targetIP)
	if domain != "" {
		fmt.Printf("%s %s\n", labelStyle.Render("Domain:"), domain)
	}
	fmt.Printf("%s %s\n", labelStyle.Render("User:"), username)
	fmt.Println()

	if len(results) == 0 {
		fmt.Println(mutedStyle.Render("No open non-web ports found."))
		return
	}

	for _, res := range results {
		statusText := res.Detail
		if res.AuthValid {
			statusText = validStyle.Render("VALID")
		}
		fmt.Printf("  %s (%s) -> %s\n", portStyle.Render(fmt.Sprintf("%d/tcp", res.Port)), res.Service, statusText)
	}
}
