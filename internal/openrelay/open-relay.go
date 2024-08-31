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

const maxRetries = 3

// IsVulnerable checks if the given IP is vulnerable to open relay attack
func IsVulnerable(ctx context.Context, ip net.IP, cfg *config.Config) (bool, error) {
	var conn net.Conn
	var err error

	addr := fmt.Sprintf("%s:25", ip)

	for retry := 0; retry < maxRetries; retry++ {
		if cfg.UseTor {
			conn, err = dialThroughTor(ctx, addr, cfg.Timeout)
			if err != nil && cfg.FallbackToDirect {
				log.Printf("Tor connection failed, falling back to direct connection for %s", addr)
				conn, err = dialDirect(ctx, addr, cfg.Timeout)
			}
		} else {
			conn, err = dialDirect(ctx, addr, cfg.Timeout)
		}

		if err != nil {
			log.Printf("Attempt %d: Failed to connect to %s: %v", retry+1, addr, err)
			time.Sleep(time.Duration(retry+1) * time.Second) // Exponential backoff
			continue
		}

		if conn == nil {
			log.Printf("Attempt %d: Connection is nil for %s", retry+1, addr)
			time.Sleep(time.Duration(retry+1) * time.Second)
			continue
		}

		defer conn.Close()

		isVulnerable, err := checkRelayVulnerability(conn, cfg.Timeout)
		if err != nil {
			log.Printf("Attempt %d: Error checking relay vulnerability for %s: %v", retry+1, addr, err)
			continue
		}

		return isVulnerable, nil
	}

	return false, fmt.Errorf("failed to check vulnerability after %d attempts", maxRetries)
}

func dialThroughTor(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("failed to create context dialer")
	}

	conn, err := contextDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial through Tor: %w", err)
	}

	return conn, nil
}

func dialDirect(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = timeout
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial directly: %w", err)
	}
	return conn, nil
}

func checkRelayVulnerability(conn net.Conn, timeout time.Duration) (bool, error) {
	if err := sendCommand(conn, "HELO example.com\r\n", "250", timeout); err != nil {
		return false, err
	}
	if err := sendCommand(conn, "MAIL FROM:<test@example.com>\r\n", "250", timeout); err != nil {
		return false, err
	}
	if err := sendCommand(conn, "RCPT TO:<test@example.org>\r\n", "250", timeout); err != nil {
		return false, nil // Not vulnerable if this fails
	}
	if err := sendCommand(conn, "DATA\r\n", "354", timeout); err != nil {
		return false, nil
	}
	if err := sendCommand(conn, "Subject: Test\r\n\r\nThis is a test.\r\n.\r\n", "250", timeout); err != nil {
		return false, nil
	}
	if err := sendCommand(conn, "QUIT\r\n", "221", timeout); err != nil {
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
