package scanner

import (
	"fmt"
	"net"
	"time"
)

// Config holds target details and credentials for non-web port checks.
type Config struct {
	IP       string
	Domain   string
	Username string
	Password string
	Timeout  time.Duration
}

// PortResult stores the scan outcome and credential test status for a port.
type PortResult struct {
	Port       int
	Service    string
	Open       bool
	AuthTested bool
	AuthValid  bool
	Detail     string
}

// defaultNonWebPorts lists common non-web service ports to inspect.
var defaultNonWebPorts = []int{
	21, 22, 23, 25, 53, 88, 110, 135, 139, 143,
	389, 445, 636, 1433, 1521, 3306, 3389, 5432, 5985, 5986,
}

// isExcludedWebPort reports whether a port is an excluded default web port.
func isExcludedWebPort(port int) bool {
	switch port {
	case 80, 443, 8080:
		return true
	default:
		return false
	}
}

// serviceName maps common non-web ports to readable service labels.
func serviceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 88:
		return "Kerberos"
	case 110:
		return "POP3"
	case 135:
		return "MSRPC"
	case 139:
		return "NetBIOS-SSN"
	case 143:
		return "IMAP"
	case 389:
		return "LDAP"
	case 445:
		return "SMB"
	case 636:
		return "LDAPS"
	case 1433:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5985:
		return "WinRM-HTTP"
	case 5986:
		return "WinRM-HTTPS"
	default:
		return "Unknown"
	}
}

// isPortOpen checks TCP reachability for a single target port.
func isPortOpen(ip string, port int, timeout time.Duration) bool {
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// testCredentialOnPort provides a modular hook for service authentication checks.
func testCredentialOnPort(cfg Config, port int) (bool, string) {
	switch port {
	case 22, 445, 3389, 5985, 5986:
		return false, "auth module ready"
	default:
		return false, "no auth check implemented"
	}
}

// ScanNonWebPorts scans non-web ports and runs credential hooks on open ports.
func ScanNonWebPorts(cfg Config) []PortResult {
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}

	var results []PortResult
	for _, port := range defaultNonWebPorts {
		if isExcludedWebPort(port) {
			continue
		}

		open := isPortOpen(cfg.IP, port, cfg.Timeout)
		if !open {
			continue
		}

		tested, detail := testCredentialOnPort(cfg, port)
		results = append(results, PortResult{
			Port:       port,
			Service:    serviceName(port),
			Open:       true,
			AuthTested: tested,
			AuthValid:  false,
			Detail:     detail,
		})
	}

	return results
}
