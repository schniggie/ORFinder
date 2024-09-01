package openrelay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/schniggie/orfinder/internal/config"
	"golang.org/x/net/proxy"
)

const maxRetries = 3

// InsecureSkipVerify disables certificate verification
var insecureTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func IsVulnerable(ctx context.Context, ip net.IP, port int, cfg *config.Config) (bool, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	log.Printf("Checking vulnerability for %s", addr)

	var conn net.Conn
	var err error

	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	if cfg.UseTor {
		log.Printf("Attempting to connect through Tor to %s", addr)
		conn, err = dialThroughTor(dialCtx, addr, cfg.Timeout)
	} else {
		log.Printf("Attempting direct connection to %s", addr)
		conn, err = dialDirect(dialCtx, addr, cfg.Timeout)
	}

	if err != nil {
		return false, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()

	log.Printf("Successfully connected to %s", addr)

	// Capture the server's greeting
	greeting, err := getServerGreeting(conn)
	if err != nil {
		log.Printf("Failed to get server greeting from %s: %v", addr, err)
	} else {
		log.Printf("Server greeting from %s: %s", addr, greeting)
	}

	var c *smtp.Client

	switch port {
	case 465:
		log.Printf("Using TLS for port 465 on %s", addr)
		tlsConn := tls.Client(conn, insecureTLSConfig)
		c, err = smtp.NewClient(tlsConn, addr)
	case 587:
		log.Printf("Using STARTTLS for port 587 on %s", addr)
		c, err = smtp.NewClient(conn, addr)
		if err == nil {
			err = c.StartTLS(insecureTLSConfig)
		}
	default:
		log.Printf("Using plain connection for port %d on %s", port, addr)
		c, err = smtp.NewClient(conn, addr)
	}

	if err != nil {
		return false, fmt.Errorf("failed to create SMTP client for %s: %w", addr, err)
	}
	defer c.Close()

	log.Printf("SMTP client created for %s", addr)

	err = c.Hello("localhost")
	if err != nil {
		return false, fmt.Errorf("HELO failed for %s: %w", addr, err)
	}
	log.Printf("HELO successful for %s", addr)

	err = c.Mail("test@example.com")
	if err != nil {
		return false, fmt.Errorf("MAIL FROM failed for %s: %w", addr, err)
	}
	log.Printf("MAIL FROM successful for %s", addr)

	err = c.Rcpt("test@example.org")
	if err != nil {
		log.Printf("RCPT TO failed for %s: %v", addr, err)
		return false, nil // Not vulnerable if this fails
	}
	log.Printf("RCPT TO successful for %s", addr)

	log.Printf("%s is potentially vulnerable to open relay", addr)
	return true, nil
}

func getServerGreeting(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(greeting), nil
}

func CheckRealEmail(ctx context.Context, ip net.IP, port int, cfg *config.Config) (bool, error) {
	randomID := randomString(10)
	sender := fmt.Sprintf("test@%s", ip)
	receiver := cfg.TestEmailAddress
	subject := fmt.Sprintf("ORFinder Test %s", randomID)
	body := "This is a test email from ORFinder."

	err := sendEmail(ctx, ip.String(), port, sender, receiver, subject, body, cfg)
	if err != nil {
		return false, fmt.Errorf("failed to send test email: %w", err)
	}

	log.Printf("Test email sent to %s, waiting for delivery", receiver)
	time.Sleep(30 * time.Second) // Wait for email to be delivered

	received, err := checkInbox(ctx, randomID, cfg)
	if err != nil {
		return false, fmt.Errorf("failed to check inbox: %w", err)
	}

	if received {
		log.Printf("Test email received, confirming open relay vulnerability")
		if err := deleteEmail(ctx, randomID, cfg); err != nil {
			log.Printf("Error deleting test email: %v", err)
		}
		return true, nil
	}

	log.Printf("Test email not received, open relay not confirmed")
	return false, nil
}

func sendEmail(ctx context.Context, host string, port int, from, to, subject, body string, cfg *config.Config) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, to, subject, body)

	var err error

	if cfg.UseTor {
		err = sendEmailOverTor(ctx, addr, from, to, []byte(msg), cfg, port)
	} else {
		err = sendEmailDirect(addr, from, to, []byte(msg), port)
	}

	return err
}

func sendEmailDirect(addr, from, to string, msg []byte, port int) error {
	var err error

	switch port {
	case 465:
		// Implicit TLS
		conn, err := tls.Dial("tcp", addr, insecureTLSConfig)
		if err != nil {
			return fmt.Errorf("failed to establish TLS connection: %w", err)
		}
		defer conn.Close()

		err = sendSMTP(conn, addr, from, to, msg)
	case 587:
		// STARTTLS
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, addr)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		if err = client.StartTLS(insecureTLSConfig); err != nil {
			return fmt.Errorf("StartTLS failed: %w", err)
		}

		err = sendSMTPWithClient(client, from, to, msg)
	default:
		// Non-TLS (e.g., port 25)
		err = smtp.SendMail(addr, nil, from, []string{to}, msg)
	}

	return err
}

func sendEmailOverTor(ctx context.Context, addr, from, to string, msg []byte, cfg *config.Config, port int) error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect through Tor: %w", err)
	}
	defer conn.Close()

	var c *smtp.Client

	switch port {
	case 465:
		// Implicit TLS
		tlsConn := tls.Client(conn, insecureTLSConfig)
		c, err = smtp.NewClient(tlsConn, addr)
	case 587:
		// STARTTLS
		c, err = smtp.NewClient(conn, addr)
		if err == nil {
			err = c.StartTLS(insecureTLSConfig)
		}
	default:
		// Non-TLS
		c, err = smtp.NewClient(conn, addr)
	}

	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer c.Close()

	return sendSMTPWithClient(c, from, to, msg)
}

func sendSMTP(conn net.Conn, addr, from, to string, msg []byte) error {
	c, err := smtp.NewClient(conn, addr)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer c.Close()

	return sendSMTPWithClient(c, from, to, msg)
}

func sendSMTPWithClient(c *smtp.Client, from, to string, msg []byte) error {
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("writing message failed: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("closing message writer failed: %w", err)
	}

	return c.Quit()
}

func checkInbox(ctx context.Context, randomID string, cfg *config.Config) (bool, error) {
	url := fmt.Sprintf("https://inboxes.com/api/v2/inbox/%s", cfg.TestEmailAddress)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Msgs []struct {
			UID string `json:"uid"`
			S   string `json:"s"`
		} `json:"msgs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	for _, msg := range result.Msgs {
		if strings.Contains(msg.S, randomID) {
			return true, nil
		}
	}

	return false, nil
}

func deleteEmail(ctx context.Context, randomID string, cfg *config.Config) error {
	url := "https://inboxes.com/api/v2/message/"
	data := fmt.Sprintf(`{"ids":["%s"]}`, randomID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, strings.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete email: status code %d", resp.StatusCode)
	}

	return nil
}

func dialThroughTor(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	var err error
	backoff := 100 * time.Millisecond
	for retry := 0; retry < 3; retry++ {
		dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("dialer does not support DialContext")
		}

		conn, err = contextDialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}

		log.Printf("Tor connection attempt %d failed: %v", retry+1, err)
		time.Sleep(backoff)
		backoff *= 2
	}
	return nil, fmt.Errorf("failed to dial through Tor after retries: %w", err)
}

func dialDirect(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	log.Printf("Attempting direct connection to %s", addr)
	var d net.Dialer
	d.Timeout = timeout
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial directly: %w", err)
	}
	log.Printf("Successfully established direct connection to %s", addr)
	return conn, nil
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
