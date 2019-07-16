package main_test

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/k0kubun/pp"
	"github.com/m-mizutani/deepalert"
	main "github.com/m-mizutani/deepalert-virustotal"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type config struct {
	SecretArn       string
	VirusTotalToken string
}

func loadConfig() config {
	var cfg config
	confPath := "test.json"
	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatal(err)
	}
	return cfg
}

var testConfig config

func init() {
	testConfig = loadConfig()
	main.Logger.SetLevel(logrus.DebugLevel)
}

func TestHandler(t *testing.T) {
	args := main.Arguments{
		Attr: deepalert.Attribute{
			Type:    deepalert.TypeIPAddr,
			Value:   "192.168.0.1",
			Context: []deepalert.AttrContext{deepalert.CtxRemote},
		},
		SecretArn: testConfig.SecretArn,
	}
	_, err := main.Handler(args)
	assert.NoError(t, err)
	// Confirm only no error
}

func TestHandlerWithClientIPAddr(t *testing.T) {
	ipaddr := os.Getenv("DA_TEST_IPADDR")
	if ipaddr == "" {
		t.Skip("DA_TEST_IPADDR is not set")
	}

	args := main.Arguments{
		Attr: deepalert.Attribute{
			Type:    deepalert.TypeIPAddr,
			Value:   ipaddr,
			Context: []deepalert.AttrContext{deepalert.CtxRemote},
		},
		SecretArn: testConfig.SecretArn,
	}

	result, err := main.Handler(args)
	assert.NoError(t, err)
	assert.NotEqual(t, 0, len(result.Contents))
	pp.Println(result)
}

func TestNoResponse(t *testing.T) {
	args := main.Arguments{
		Attr: deepalert.Attribute{
			Type: deepalert.TypeDomainName,
		},
		SecretArn: os.Getenv("DA_TEST_SECRET"),
	}

	entity, err := main.Handler(args)
	assert.NoError(t, err)
	assert.Nil(t, entity)
}
