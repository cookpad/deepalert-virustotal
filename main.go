package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/m-mizutani/deepalert"
	"github.com/pkg/errors"
)

type Arguments struct {
	Attr      deepalert.Attribute
	SecretArn string
}

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

	report, err := vt.QueryIPAddr(ipaddr)
	if err != nil {
		return nil, err
	}
	/*
		mwReports, err := traceMalware(report, &vt)
		if err != nil {
			return nil, err
		}

		remote := ar.ReportOpponentHost{
			IPAddr:         []string{ipaddr},
			RelatedMalware: mwReports,
			RelatedDomains: traceDomain(report.Resolutions),
			RelatedURLs:    traceURL(report.DetectedURLs),
		}

		page := ar.NewReportPage()
		page.Title = fmt.Sprintf("VirusTotal Report of %s", ipaddr)
		page.OpponentHosts = append(page.OpponentHosts, remote)

	*/

	return nil, nil
}

func handler(args Arguments) (*deepalert.TaskResult, error) {
	if args.Attr.Match(deepalert.CtxRemote, deepalert.TypeIPAddr) {
		return insecptRemoteIPAddr(args.Attr.Value, args.SecretArn)
	}

	return nil, nil
}

func lambdaHandler(ctx context.Context, attr deepalert.Attribute) (*deepalert.TaskResult, error) {
	args := Arguments{
		Attr:      attr,
		SecretArn: os.Getenv("SecretArn"),
	}
	return handler(args)
}

func main() {
	deepalert.StartInspector(lambdaHandler, "virustotal",
		os.Getenv("ContentTopic"), os.Getenv("AttributeTopic"))
}
