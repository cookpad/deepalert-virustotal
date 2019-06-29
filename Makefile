DEPLOY_CONFIG ?= deploy.jsonnet
TEMPLATE ?= template.jsonnet

CWD := ${CURDIR}
CODE_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
SAM_FILE=$(CODE_DIR)/sam.json
BINPATH := $(CODE_DIR)/build/main

TEMPLATE_FILE := $(CODE_DIR)/template.json

all: deploy

test:
	go test -v

clean:
	rm build/main

build: $(BINPATH)

$(BINPATH): $(CODE_DIR)/*.go
	cd $(CODE_DIR) && env GOARCH=amd64 GOOS=linux go build -o build/main $(CODE_DIR) && cd $(CWD)

$(TEMPLATE_FILE): $(TEMPLATE)
	jsonnet $(TEMPLATE) -o $(TEMPLATE_FILE)

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
