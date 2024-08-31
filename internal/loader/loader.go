package loader

import (
	"context"
	"fmt"

	"github.com/oschwald/maxminddb-golang"
)

type record struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Load fetches IP ranges for the given country code
func Load(ctx context.Context, countryCode string) ([]string, error) {
	db, err := maxminddb.Open("/tmp/GeoLite2-Country.mmdb")
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoLite2 database: %w", err)
	}
	defer db.Close()

	var ranges []string
	networks := db.Networks(maxminddb.SkipAliasedNetworks)

	for networks.Next() {
		select {
		case <-ctx.Done():
			return ranges, ctx.Err()
		default:
			var record record
			network, err := networks.Network(&record)
			if err != nil {
				continue
			}

			if record.Country.IsoCode == countryCode {
				ranges = append(ranges, network.String())
			}
		}
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("no IP ranges found for country code: %s", countryCode)
	}

	return ranges, nil
}
