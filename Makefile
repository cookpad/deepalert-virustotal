DEPLOY_CONFIG ?= deploy.jsonnet
TEMPLATE ?= template.jsonnet

CODE_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
CWD := ${CURDIR}
BINPATH := build/main

TEMPLATE_FILE := template.json
SAM_FILE := sam.yml
BASE_FILE := $(CODE_DIR)/base.libsonnet

all: deploy

test:
	go test -v

clean:
	rm build/main

build: $(BINPATH)

$(BINPATH): $(CODE_DIR)/*.go
	cd $(CODE_DIR) && env GOARCH=amd64 GOOS=linux go build -o $(CWD)/build/main && cd $(CWD)

$(TEMPLATE_FILE): $(TEMPLATE) $(BASE_FILE)
	jsonnet -J $(CODE_DIR) $(TEMPLATE) -o $(TEMPLATE_FILE)

$(SAM_FILE): $(TEMPLATE_FILE) $(BINPATH)
	aws cloudformation package \
		--region $(shell jsonnet $(DEPLOY_CONFIG) | jq .Region) \
		--template-file $(TEMPLATE_FILE) \
		--s3-bucket $(shell jsonnet $(DEPLOY_CONFIG) | jq .CodeS3Bucket) \
		--s3-prefix $(shell jsonnet $(DEPLOY_CONFIG) | jq .CodeS3Prefix) \
		--output-template-file $(SAM_FILE)

deploy: $(SAM_FILE)
	aws cloudformation deploy \
		--region $(shell jsonnet $(DEPLOY_CONFIG) | jq .Region) \
		--template-file $(SAM_FILE) \
		--stack-name $(shell jsonnet $(DEPLOY_CONFIG) | jq .StackName) \
		--capabilities CAPABILITY_IAM
