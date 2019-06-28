StackName := $(shell jsonnet $(DEPLOY_CONFIG) | jq .StackName )
Region := $(shell jsonnet $(DEPLOY_CONFIG) | jq .Region )
CodeS3Bucket := $(shell jsonnet $(DEPLOY_CONFIG) | jq .CodeS3Bucket )
CodeS3Prefix := $(shell jsonnet $(DEPLOY_CONFIG) | jq .CodeS3Prefix )

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

$(BINPATH): $(CODE_DIR)/*.go
	cd $(CODE_DIR) && env GOARCH=amd64 GOOS=linux go build -o build/main $(CODE_DIR) && cd $(CWD)

$(TEMPLATE_FILE): $(TEMPLATE)
	jsonnet $(TEMPLATE) -o $(TEMPLATE_FILE)

$(SAM_FILE): $(TEMPLATE_FILE) $(BINPATH)
	aws cloudformation package \
		--region $(Region) \
		--template-file $(TEMPLATE_FILE) \
		--s3-bucket $(CodeS3Bucket) \
		--s3-prefix $(CodeS3Prefix) \
		--output-template-file $(SAM_FILE)

deploy: $(SAM_FILE)
	aws cloudformation deploy \
		--region $(Region) \
		--template-file $(SAM_FILE) \
		--stack-name $(StackName) \
		--capabilities CAPABILITY_IAM
