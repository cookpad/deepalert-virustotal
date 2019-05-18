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

	var hashes []string
	for _, sample := range samples {
		hashes = append(hashes, sample.SHA256)
	}

	mwReport, err := vt.QueryFileBulk(hashes)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to query in traceMalware")
	}

	convMalwareReport := func(targets []VtSample, relation string) {
		for _, sample := range targets {
			t, err := time.Parse("2006-01-02 15:04:05", sample.Date)
			if err != nil {
				log.Println("Error: Invalid time format of VT result, ", sample.Date)
				continue
			}

			mwTemp = append(mwTemp, ar.ReportMalware{
				SHA256:    sample.SHA256,
				Timestamp: t,
				Relation:  relation,
			})
		}
	}

	for _, report := range mwReport {

	}

	return nil, nil
}

/*
func traceMalware(report VirusTotalIPAddrReport, vt *VirusTotal) ([]ar.ReportMalware, error) {
	mwTemp := []ar.ReportMalware{}
	mwReport := []ar.ReportMalware{}
	hashList := []string{}

	targetVendors := []string{
		"Kaspersky",
		"TrendMicro",
		"Sophos",
		"Microsoft",
		"Symantec",
	}

	convMalwareReport := func(targets []VtSample, relation string) {
		for _, sample := range targets {
			t, err := time.Parse("2006-01-02 15:04:05", sample.Date)
			if err != nil {
				log.Println("Error: Invalid time format of VT result, ", sample.Date)
				continue
			}

			mwTemp = append(mwTemp, ar.ReportMalware{
				SHA256:    sample.SHA256,
				Timestamp: t,
				Relation:  relation,
			})
		}
	}
	convMalwareReport(report.DetectedCommunicatingSamples, "communicated")
	convMalwareReport(report.DetectedDownloadedSamples, "downloaded")
	convMalwareReport(report.DetectedReferrerSamples, "emmbeded")

	const maxItemCount int = 8

	sort.Slice(mwTemp, func(i, j int) bool { // Reverse sort
		return mwTemp[i].Timestamp.After(mwTemp[j].Timestamp)
	})

	for i := 0; i < maxItemCount && i < len(mwTemp); i++ {
		mwReport = append(mwReport, mwTemp[i])
		hashList = append(hashList, mwTemp[i].SHA256)
	}

	cache, err := createMalwareCache(hashList, vt)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(mwReport); i++ {
		r := &mwReport[i]
		scanResult, ok := cache[r.SHA256]
		if !ok {
			log.Println("No scan result:", r.SHA256)
			continue
		}

		for _, vendor := range targetVendors {
			scan, ok := scanResult.Scans[vendor]
			scanReport := ar.ReportMalwareScan{Vendor: vendor, Source: "VirusTotal"}

			if ok && scan.Detected {
				scanReport.Positive = true
				scanReport.Name = scan.Result
			}

			r.Scans = append(r.Scans, scanReport)
		}
	}

	return mwReport, nil
}
*/
