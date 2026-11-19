package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/penguinshero/opspray/internal/scanner"
	"github.com/penguinshero/opspray/internal/ui"
	"github.com/spf13/cobra"
)

var (
	targetIP string
	domain   string
	username string
	password string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "opspray",
	Short: "Authorized internal credential reuse validator",
	Long:  "Authorized internal credential reuse validator across open network services.",
	RunE:  runOpspray,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// init registers command-line flags and customizes help output.
func init() {
	rootCmd.Flags().StringVarP(&targetIP, "ip", "i", "", "Target IP address")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target Active Directory domain")
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Target username")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "Target password")

	rootCmd.SetHelpFunc(renderCleanHelp)
}

// renderCleanHelp prints a clean, banner-free help menu styled with Lipgloss.
func renderCleanHelp(cmd *cobra.Command, args []string) {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	labelStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	flagStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))

	fmt.Println(titleStyle.Render(cmd.Name()) + " - " + cmd.Short)
	fmt.Println()
	fmt.Println(labelStyle.Render("Usage:"))
	fmt.Printf("  %s -i <ip> -d <domain> -u <username> -p <password>\n", cmd.Name())
	fmt.Println()
	fmt.Println(labelStyle.Render("Flags:"))
	fmt.Printf("  %s    Target IP address\n", flagStyle.Render("-i, --ip"))
	fmt.Printf("  %s    Target Active Directory domain\n", flagStyle.Render("-d, --domain"))
	fmt.Printf("  %s    Target username\n", flagStyle.Render("-u, --username"))
	fmt.Printf("  %s    Target password\n", flagStyle.Render("-p, --password"))
	fmt.Printf("  %s    Show help menu\n", flagStyle.Render("-h, --help"))
}

// runOpspray validates required inputs and runs the modular scanner and UI renderer.
func runOpspray(cmd *cobra.Command, args []string) error {
	if targetIP == "" || username == "" || password == "" {
		return fmt.Errorf("missing required flags: -i, -u, and -p are required")
	}

	cfg := scanner.Config{
		IP:       targetIP,
		Domain:   domain,
		Username: username,
		Password: password,
		Timeout:  2 * time.Second,
	}

	results := scanner.ScanNonWebPorts(cfg)
	ui.RenderResults(targetIP, domain, username, results)
	return nil
}
