package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type VirusTotal struct {
	endpoint string
	token    string
}

type vtScanResult struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
	Update   string `json:"update"`
	Version  string `json:"version"`
}

type VirusTotalFileReport struct {
	ResponseCode int    `json:"response_code"`
	SHA256       string `json:"sha256"`
	ScanDate     string `json:"scan_date"`
	Positives    int    `json:"positives"`
	Total        int    `json:"total"`
	Scans        map[string]vtScanResult
}

// VtSample is used in main process
type VtSample struct {
	SHA256    string `json:"sha256"`
	Positives int    `json:"positives"`
	Total     int    `json:"total"`
	Date      string `json:"date"`

	// An original field to indicate type of relation with IPaddr/domain
	relation string
}

type vtResolution struct {
	LastResolved string `json:"last_resolved"`
	HostName     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
}

type vtURL struct {
	URL       string `json:"url"`
	Positives int    `json:"positives"`
	Total     int    `json:"total"`
	ScanDate  string `json:"scan_date"`
	Country   string `json:"country"`
}

type VirusTotalIPAddrReport struct {
	ResponseCode                 int            `json:"response_code"`
	DetectedURLs                 []vtURL        `json:"detected_urls"`
	Resolutions                  []vtResolution `json:"resolutions"`
	DetectedDownloadedSamples    []VtSample     `json:"detected_downloaded_samples"`
	DetectedCommunicatingSamples []VtSample     `json:"detected_communicating_samples"`
	DetectedReferrerSamples      []VtSample     `json:"detected_referrer_samples"`
}

type VirusTotalDomainReport struct {
	ResponseCode                 int            `json:"response_code"`
	WhoisTimestamp               int            `json:"whois_timestamp"`
	Whois                        string         `json:"whois"`
	DetectedURLs                 []vtURL        `json:"detected_urls"`
	DetectedReferrerSamples      []VtSample     `json:"detected_referrer_samples"`
	DetectedDownloadedSamples    []VtSample     `json:"detected_downloaded_samples"`
	DetectedCommunicatingSamples []VtSample     `json:"detected_communicating_samples"`
	UndetectedReferrerSamples    []VtSample     `json:"undetected_referrer_samples"`
	Resolutions                  []vtResolution `json:"resolutions"`
	SubDomains                   []string       `json:"subdomains"`
	Categories                   []string       `json:"categories"`
	VerboseMsg                   string         `json:"verbose_msg"`

	UndetectedURLs []interface{} `json:"undetected_urls"`
	DomainSiblings []interface{} `json:"domain_siblings"`
	// unknown schemes:
	// - undetected_urls
	// - domain_siblings
}

func newVirusTotal(token string) VirusTotal {
	vt := VirusTotal{}
	vt.endpoint = "https://www.virustotal.com/vtapi/v2"
	vt.token = token
	return vt
}

func (x *VirusTotal) Query(api string, param url.Values, res interface{}) error {
	baseURL := fmt.Sprintf("%s/%s", x.endpoint, api)
	apiURL, err := url.Parse(baseURL)
	param.Set("apikey", x.token)
	apiURL.RawQuery = param.Encode()

	req, err := http.NewRequest("GET", apiURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Fail to create VT query request")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	// pp.Println("code:", resp.StatusCode)

	if resp.StatusCode == 204 {
		// Hits API rate limit, wait 30 sec and retry.
		var wait time.Duration = 30 * time.Second
		Logger.WithField("second", wait).Debug("Sleeping for next query...")
		time.Sleep(wait)
		return x.Query(api, param, res)
	}

	if err != nil {
		return errors.Wrap(err, "VT API error")
	}

	resData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Fail to read response from VT")
	}

	if resp.StatusCode != 200 {
		Logger.WithFields(logrus.Fields{
			"code":   resp.StatusCode,
			"result": string(resData),
		}).Error("Response from VirusTotal")
		return fmt.Errorf("Status code is not 200: %d", resp.StatusCode)
	}

	err = json.Unmarshal(resData, &res)
	if err != nil {
		return errors.Wrapf(err, "Fail to parse JSON of a response from VT")
	}

	// _ = ioutil.WriteFile("vt.json", resData, 0644)
	return nil
}

func (x *VirusTotal) QueryFile(sha256 string) (VirusTotalFileReport, error) {
	qs := url.Values{}
	qs.Set("resource", sha256)
	fileReport := VirusTotalFileReport{}
	err := x.Query("file/report", qs, &fileReport)
	if err != nil {
		return fileReport, err
	}
	return fileReport, nil
}

func (x *VirusTotal) QueryFileBulk(sha256 []string) ([]VirusTotalFileReport, error) {
	batchSize := 4
	results := []VirusTotalFileReport{}

	for i := 0; i < len(sha256); i += batchSize {
		ep := i + batchSize
		if len(sha256) < ep {
			ep = len(sha256)
		}
		targets := sha256[i:ep]

		qs := url.Values{}
		qs.Set("resource", strings.Join(targets, ","))
		// pp.Println("Query:", targets)

		if len(targets) > 1 {
			fileReports := []VirusTotalFileReport{}
			err := x.Query("file/report", qs, &fileReports)
			if err != nil {
				return nil, err
			}

			results = append(results, fileReports...)
		} else {
			fileReport := VirusTotalFileReport{}
			err := x.Query("file/report", qs, &fileReport)
			if err != nil {
				return nil, err
			}

			results = append(results, fileReport)
		}
	}

	return results, nil
}

func (x *VirusTotal) QueryIPAddr(ipaddr string) (VirusTotalIPAddrReport, error) {
	qs := url.Values{}
	qs.Set("ip", ipaddr)
	report := VirusTotalIPAddrReport{}
	err := x.Query("ip-address/report", qs, &report)
	if err != nil {
		return report, err
	}
	return report, nil
}

func (x *VirusTotal) QueryDomain(domain string) (VirusTotalDomainReport, error) {
	qs := url.Values{}
	qs.Set("domain", domain)
	report := VirusTotalDomainReport{}
	err := x.Query("domain/report", qs, &report)
	if err != nil {
		return report, err
	}
	return report, nil
}
