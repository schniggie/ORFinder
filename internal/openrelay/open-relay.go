package openrelay

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/schniggie/orfinder/internal/config"
	"golang.org/x/net/proxy"
)

// IsVulnerable checks if the given IP is vulnerable to open relay attack
func IsVulnerable(ctx context.Context, ip net.IP, cfg *config.Config) (bool, error) {
	var conn net.Conn
	var err error

	addr := fmt.Sprintf("%s:25", ip)

	if cfg.UseTor {
		dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
		if err != nil {
			log.Printf("Failed to create SOCKS5 dialer: %v. Falling back to direct connection.", err)
			cfg.UseTor = false
		} else {
			contextDialer, ok := dialer.(proxy.ContextDialer)
			if !ok {
				return false, fmt.Errorf("failed to create context dialer")
			}
			conn, err = contextDialer.DialContext(ctx, "tcp", addr)
		}
	}

	if !cfg.UseTor {
		d := net.Dialer{Timeout: cfg.Timeout}
		conn, err = d.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return false, fmt.Errorf("failed to connect: %w", err)
	}
	if conn == nil {
		return false, fmt.Errorf("connection is nil")
	}
	defer conn.Close()

	if err := sendCommand(conn, "HELO example.com\r\n", "250", cfg.Timeout); err != nil {
		return false, err
	}
	if err := sendCommand(conn, "MAIL FROM:<test@example.com>\r\n", "250", cfg.Timeout); err != nil {
		return false, err
	}
	if err := sendCommand(conn, "RCPT TO:<test@example.org>\r\n", "250", cfg.Timeout); err != nil {
		return false, nil // Not vulnerable if this fails
	}
	if err := sendCommand(conn, "DATA\r\n", "354", cfg.Timeout); err != nil {
		return false, nil
	}
	if err := sendCommand(conn, "Subject: Test\r\n\r\nThis is a test.\r\n.\r\n", "250", cfg.Timeout); err != nil {
		return false, nil
	}
	if err := sendCommand(conn, "QUIT\r\n", "221", cfg.Timeout); err != nil {
		return false, nil
	}

	return true, nil // Potentially vulnerable if all commands succeed
}

func sendCommand(conn net.Conn, cmd, expectedResponse string, timeout time.Duration) error {
	err := conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return fmt.Errorf("failed to set deadline: %w", err)
	}

	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return fmt.Errorf("failed to send command: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if string(buf[:n])[:3] != expectedResponse {
		return fmt.Errorf("unexpected response: %s", string(buf[:n]))
	}

	return nil
}
