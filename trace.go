package main

import (
	"log"
	"time"

	"github.com/m-mizutani/deepalert"
	"github.com/pkg/errors"
)

func traceMalware(samples []VtSample, vt *VirusTotal) ([]deepalert.EntityMalware, error) {
	targetVendors := []string{
		"Kaspersky",
		"TrendMicro",
		"Sophos",
		"Microsoft",
		"Symantec",
	}

	sampleMap := make(map[string]*VtSample)
	for _, s := range samples {
		sampleMap[s.SHA256] = &s
	}

	var hashes []string
	for _, sample := range samples {
		hashes = append(hashes, sample.SHA256)
	}

	mwReports, err := vt.QueryFileBulk(hashes)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to query in traceMalware")
	}

	var mwEntities []deepalert.EntityMalware

	for _, report := range mwReports {
		// Pickup sample
		sample, ok := sampleMap[report.SHA256]
		if !ok {
			log.Printf("Error: mismatch result for %s\n", report.SHA256)
			continue
		}

		t, err := time.Parse("2006-01-02 15:04:05", sample.Date)
		if err != nil {
			log.Println("Error: Invalid time format of VT result, ", sample.Date)
			continue
		}

		// Filter scans
		var scans []deepalert.EntityMalwareScan
		for _, vendor := range targetVendors {
			if scan, ok := report.Scans[vendor]; ok {
				scans = append(scans, deepalert.EntityMalwareScan{
					Vendor:   vendor,
					Name:     scan.Result,
					Positive: scan.Detected,
					Source:   sourceName,
				})
			}
		}

		mwEntities = append(mwEntities, deepalert.EntityMalware{
			SHA256:    report.SHA256,
			Timestamp: t,
			Relation:  sample.relation,
			Scans:     scans,
		})
	}

	return mwEntities, nil
}
