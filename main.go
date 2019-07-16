package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/m-mizutani/deepalert"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Arguments struct {
	Attr      deepalert.Attribute
	SecretArn string
}

const (
	sourceName = "VirusTotal"
)

var (
	// Logger can be modified by test code
	Logger = logrus.New()
)

func getSecretValues(secretArn string, values interface{}) error {
	// sample: arn:aws:secretsmanager:ap-northeast-1:1234567890:secret:mytest
	arn := strings.Split(secretArn, ":")
	if len(arn) != 7 {
		return errors.New(fmt.Sprintf("Invalid SecretsManager ARN format: %s", secretArn))
	}
	region := arn[3]

	ssn := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	mgr := secretsmanager.New(ssn)

	result, err := mgr.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	})

	if err != nil {
		return errors.Wrapf(err, "Fail to retrieve secret values: %s", secretArn)
	}

	err = json.Unmarshal([]byte(*result.SecretString), values)
	if err != nil {
		return errors.Wrapf(err, "Fail to parse secret values as JSON: %s", secretArn)
	}

	return nil
}

type vtSecrets struct {
	VirusTotalToken string `json:"virustotal_token"`
}

func insecptRemoteIPAddr(ipaddr, secretArn string) (*deepalert.TaskResult, error) {
	var secrets vtSecrets
	if err := getSecretValues(secretArn, &secrets); err != nil {
		return nil, err
	}

	vt := newVirusTotal(secrets.VirusTotalToken)

	vtReport, err := vt.QueryIPAddr(ipaddr)
	if err != nil {
		return nil, errors.Wrapf(err, "Fail to query IP address to VirusTotal: %s", ipaddr)
	}

	// merge domain names
	var domainReport []deepalert.EntityDomain
	for _, resolution := range vtReport.Resolutions {
		t, _ := time.Parse("2006-01-02 15:04:05", resolution.LastResolved)
		domainReport = append(domainReport, deepalert.EntityDomain{
			Name:      resolution.HostName,
			Timestamp: t,
			Source:    sourceName,
		})
	}
	sort.Slice(domainReport, func(i, j int) bool { return domainReport[i].Timestamp.After(domainReport[j].Timestamp) })

	// merge URLs
	var urlReport []deepalert.EntityURL
	for _, url := range vtReport.DetectedURLs {
		t, _ := time.Parse("2006-01-02 15:04:05", url.ScanDate)
		urlReport = append(urlReport, deepalert.EntityURL{
			URL:       url.URL,
			Timestamp: t,
			Source:    sourceName,
		})
	}
	sort.Slice(urlReport, func(i, j int) bool { return urlReport[i].Timestamp.After(urlReport[j].Timestamp) })

	// merge detected samples
	var samples []VtSample
	extend := func(sampleSet []VtSample, relation string) {
		for _, s := range sampleSet {
			s.relation = relation
			samples = append(samples, s)
		}
	}
	extend(vtReport.DetectedDownloadedSamples, "downloaded")
	extend(vtReport.DetectedCommunicatingSamples, "communicated")
	extend(vtReport.DetectedReferrerSamples, "referrer")

	sort.Slice(samples, func(i, j int) bool {
		return samples[i].Date > samples[j].Date
	})

	// Maximum number of samples that will be queried is defined because of limit of VT API.
	sampleLimit := 8
	var targets []VtSample
	targets = append(targets, samples...)
	if len(targets) > sampleLimit {
		targets = targets[:sampleLimit]
	}

	malwareReport, err := traceMalware(targets, &vt)
	if err != nil {
		return nil, errors.Wrapf(err, "Fail to trace Malware for %s", ipaddr)
	}

	host := deepalert.ReportHost{
		RelatedDomains: domainReport,
		RelatedMalware: malwareReport,
		RelatedURLs:    urlReport,
	}

	return &deepalert.TaskResult{Contents: []deepalert.ReportContentEntity{&host}}, nil
}

func insecptRemoteDomain(ipaddr, secretArn string) (*deepalert.TaskResult, error) {
	return nil, nil
}

func handler(args Arguments) (*deepalert.TaskResult, error) {
	switch {
	case args.Attr.Match(deepalert.CtxRemote, deepalert.TypeIPAddr):
		return insecptRemoteIPAddr(args.Attr.Value, args.SecretArn)
	default:
		return nil, nil
	}
}

func lambdaHandler(ctx context.Context, attr deepalert.Attribute) (*deepalert.TaskResult, error) {
	args := Arguments{
		Attr:      attr,
		SecretArn: os.Getenv("SecretArn"),
	}
	return handler(args)
}

func main() {
	Logger.SetFormatter(&logrus.JSONFormatter{})
	Logger.SetLevel(logrus.InfoLevel)

	deepalert.StartInspector(lambdaHandler, "virustotal",
		os.Getenv("ContentTopic"), os.Getenv("AttributeTopic"))
}
