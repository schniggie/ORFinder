package config

import (
	"time"
)

type Config struct {
	CountryCode string
	Concurrency int
	Timeout     time.Duration
	UserAgent   string
	Debug       bool
	UseTor      bool
	OutputFile  string
}

func DefaultConfig() *Config {
	return &Config{
		CountryCode: "RU",
		Concurrency: 100,
		Timeout:     5 * time.Second,
		UserAgent:   "ORFinder/1.0 (Security Research; root@schniggie.de)",
		Debug:       false,
		UseTor:      false,
		OutputFile:  "",
	}
}
