package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/schniggie/orfinder/internal/config"
	"github.com/schniggie/orfinder/internal/loader"
	"github.com/schniggie/orfinder/internal/scanner"
)

func main() {
	cfg := config.DefaultConfig()

	// Parse command-line flags
	flag.StringVar(&cfg.CountryCode, "c", cfg.CountryCode, "Country code (e.g., us, ru, fr)")
	flag.IntVar(&cfg.Concurrency, "n", cfg.Concurrency, "Number of concurrent scans (default: 100, tor: 10")
	flag.DurationVar(&cfg.Timeout, "t", cfg.Timeout, "Timeout for each scan")
	flag.BoolVar(&cfg.Debug, "debug", cfg.Debug, "Enable debug output")
	flag.BoolVar(&cfg.UseTor, "tor", cfg.UseTor, "Use Tor for scanning (requires a running Tor proxy on 127.0.0.1:9050)")
	flag.StringVar(&cfg.OutputFile, "o", cfg.OutputFile, "Output file for vulnerable servers")
	flag.Parse()

	if cfg.UseTor {
		cfg.Concurrency = 10 // Reduce concurrency when using Tor
	}
	flag.Parse()

	// Set up logging
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Print welcome message
	welcome()

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Received interrupt signal, shutting down...")
		cancel()
	}()

	// Create output file if specified
	var outputFile *os.File
	var err error
	if cfg.OutputFile != "" {
		outputFile, err = os.Create(cfg.OutputFile)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer outputFile.Close()
	}

	// Load IP ranges
	log.Printf("Loading IP ranges for country code: %s", cfg.CountryCode)
	ipRanges, err := loader.Load(ctx, cfg.CountryCode)
	if err != nil {
		log.Fatalf("Failed to load IP ranges: %v", err)
	}
	log.Printf("Loaded %d IP ranges", len(ipRanges))

	// Create a wait group and semaphore for managing concurrency
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Concurrency)

	// Create a channel to collect vulnerable servers
	vulnerableServers := make(chan string, cfg.Concurrency)

	// Start a goroutine to write vulnerable servers to the output file
	go func() {
		for server := range vulnerableServers {
			if outputFile != nil {
				_, err := fmt.Fprintln(outputFile, server)
				if err != nil {
					log.Printf("Error writing to output file: %v", err)
				}
			}
			fmt.Println(server)
		}
	}()

	// Start scanning
	log.Printf("Starting scan with concurrency: %d", cfg.Concurrency)
	startTime := time.Now()

	for _, ipRange := range ipRanges {
		select {
		case <-ctx.Done():
			log.Println("Scan cancelled")
			return
		case sem <- struct{}{}:
			wg.Add(1)
			go func(ipRange string) {
				defer wg.Done()
				defer func() { <-sem }()

				if err := scanner.Scan(ctx, ipRange, cfg, vulnerableServers); err != nil {
					log.Printf("Error scanning %s: %v", ipRange, err)
				}
			}(ipRange)
		}
	}

	// Wait for all scans to complete
	wg.Wait()
	close(vulnerableServers)

	// Print summary
	duration := time.Since(startTime)
	log.Printf("Scan completed in %v", duration)
}

func welcome() {
	fmt.Print(`
   ____  ____  ______ _           __         
  / __ \/ __ \/ ____/(_)___  ____/ /__  _____
 / / / / /_/ / /_   / / __ \/ __  / _ \/ ___/
/ /_/ / _, _/ __/  / / / / / /_/ /  __/ /    
\____/_/ |_/_/    /_/_/ /_/\__,_/\___/_/     
                                             
Open Relay Finder - Security Research Tool
Use responsibly and ethically.
Contact: root@schniggie.de (Original by Nitrax <nitrax@lokisec.fr>)
`)
}
