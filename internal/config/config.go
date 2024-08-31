package config

import (
	"time"
)

type Config struct {
	CountryCode      string
	Concurrency      int
	Timeout          time.Duration
	UserAgent        string
	Debug            bool
	UseTor           bool
	FallbackToDirect bool
	OutputFile       string
	Ports            []int
	CheckRealEmail   bool
	TestEmailAddress string
}

func DefaultConfig() *Config {
	return &Config{
		CountryCode:      "RU",
		Concurrency:      100,
		Timeout:          15 * time.Second,
		UserAgent:        "ORFinder/1.0 (Security Research; root@schniggie.de)",
		Debug:            false,
		UseTor:           false,
		FallbackToDirect: false,
		OutputFile:       "",
		Ports:            []int{25, 465, 587},
		CheckRealEmail:   false,
		TestEmailAddress: "orfinder@replyloop.com",
	}
}
