package main_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/m-mizutani/deepalert"
	main "github.com/m-mizutani/deepalert-crowdstrike-falcon"
)

func TestHandler(t *testing.T) {
	args := main.Arguments{
		Attr: deepalert.Attribute{
			Type:  deepalert.TypeIPAddr,
			Value: "192.168.0.1",
		},
		SecretArn: os.Getenv("DA_TEST_SECRET"),
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
			Type:  deepalert.TypeIPAddr,
			Value: ipaddr,
		},
		SecretArn: os.Getenv("DA_TEST_SECRET"),
	}
	entity, err := main.Handler(args)
	assert.NoError(t, err)

	host, ok := entity.(*deepalert.ReportHost)
	require.True(t, ok)
	assert.NotEqual(t, 0, len(host.IPAddr))
	assert.NotEqual(t, 0, len(host.OS))
	assert.NotEqual(t, 0, len(host.MACAddr))
	assert.NotEqual(t, 0, len(host.HostName))
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
