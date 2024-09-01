package utils

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

// GenerateRandomString creates a random string of the specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// IsValidIP checks if the given string is a valid IP address
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// FormatDuration formats a duration in a human-readable format
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func VerifyTorConnection() error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.Dial("tcp", "check.torproject.org:80")
	if err != nil {
		return fmt.Errorf("failed to connect through Tor: %w", err)
	}
	defer conn.Close()

	fmt.Println("Successfully connected through Tor")
	return nil
}
