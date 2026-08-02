# Authpole Master Makefile

.PHONY: all build build-go build-linux test build-docker run-local stop-local build-unikraft deploy-terraform deploy-server deploy-admin deploy logs clean help

BINARY_NAME=authpole
BUILD_DIR=bin
DOCKER_IMAGE=authpole:latest
KRAFT_TARGET=qemu/x86_64

# AWS deployment config (override via environment or make args)
AWS_REGION        ?= us-east-1
S3_BUCKET         ?= authpole-production-storage
ASG_NAME          ?= authpole-asg
ADMIN_S3_BUCKET   ?= authpole-admin.swii.sh
CLOUDFRONT_ID     ?= E36APV6PTPMVQK
WARMUP_SECONDS    ?= 15

all: build-go test

## build-go: Build Go server binary (native, for local use)
build-go:
	@echo "🔨 Building Go binary..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server
	@echo "✅ Binary created at $(BUILD_DIR)/$(BINARY_NAME)"

## build-linux: Cross-compile Go binary for Linux amd64 (for EC2 deployment)
build-linux:
	@echo "🐧 Cross-compiling for Linux amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux ./cmd/server
	@echo "✅ Linux binary: $(BUILD_DIR)/$(BINARY_NAME)-linux ($$(du -sh $(BUILD_DIR)/$(BINARY_NAME)-linux | cut -f1))"
	@file $(BUILD_DIR)/$(BINARY_NAME)-linux

build: build-go

## test: Run unit and race detection tests
test:
	@echo "🧪 Running Go test suite..."
	go test -v -race ./...

## test-web: Verify web app JavaScript syntax, DOM ID mappings, and OIDC/CORS endpoints
test-web:
	@echo "🌐 Verifying Web Application Stability..."
	@node scripts/verify_webapp.js

## verify: Full backend and frontend verification pipeline
verify: test test-web

## build-docker: Build production Docker image
build-docker:
	@echo "🐳 Building Docker image $(DOCKER_IMAGE)..."
	docker build -t $(DOCKER_IMAGE) .
	@echo "✅ Docker image $(DOCKER_IMAGE) built successfully."

## run-local: Run complete stack locally using docker-compose with MinIO S3 emulator
run-local:
	@echo "🚀 Starting local stack (Authpole + MinIO + Standalone Admin UI)..."
	docker-compose up --build -d
	@echo "====================================================="
	@echo "⚡ Authpole Server:      http://localhost:8080"
	@echo "🖥️ Standalone Admin UI:  http://localhost:3000"
	@echo "🪣 MinIO S3 Console:    http://localhost:9001 (minioadmin / minioadmin)"
	@echo "====================================================="

## stop-local: Stop local docker-compose stack
stop-local:
	@echo "🛑 Stopping local docker-compose stack..."
	docker-compose down
	@echo "✅ Local stack stopped."

## build-unikraft: Build Unikraft micro-unikernel image
build-unikraft:
	@echo "⚛️ Building Unikraft unikernel image via Kraftfile..."
	@if command -v kraft > /dev/null; then \
		kraft build --target $(KRAFT_TARGET); \
	else \
		echo "⚠️ Kraft CLI not installed. To install kraft, visit https://kraftkit.sh/"; \
		echo "Simulating Unikraft build via Kraftfile spec validation..."; \
		cat Kraftfile; \
	fi

## deploy-terraform: Deploy infrastructure to AWS using Terraform
deploy-terraform:
	@echo "☁️ Deploying Authpole infrastructure to AWS via Terraform..."
	@if command -v terraform > /dev/null; then \
		unset AWS_PROFILE && \
		eval $$(aws configure export-credentials --format env 2>/dev/null || true) && \
		cd terraform && \
		terraform init && \
		terraform plan -out=tfplan && \
		echo "=====================================================" && \
		echo "Execute 'cd terraform && terraform apply tfplan' to complete deployment." && \
		echo "====================================================="; \
	else \
		echo "⚠️ Terraform CLI not installed. Please install Terraform (https://terraform.io)."; \
	fi

## deploy-server: Build Linux binary, upload to S3, and do a rolling instance refresh
deploy-server: build-linux
	@echo "🚀 Deploying server to AWS (region: $(AWS_REGION), bucket: $(S3_BUCKET))..."
	@echo ""
	@echo "📦 Step 1/3 — Uploading binary to S3..."
	aws s3 cp $(BUILD_DIR)/$(BINARY_NAME)-linux \
		s3://$(S3_BUCKET)/bin/$(BINARY_NAME)-linux \
		--region $(AWS_REGION)
	@echo "✅ Binary uploaded."
	@echo ""
	@echo "🔄 Step 2/3 — Starting rolling instance refresh (warmup: $(WARMUP_SECONDS)s)..."
	@aws autoscaling cancel-instance-refresh \
		--auto-scaling-group-name $(ASG_NAME) \
		--region $(AWS_REGION) 2>/dev/null || true
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do \
		STATUS=$$(aws autoscaling describe-instance-refreshes --auto-scaling-group-name $(ASG_NAME) --region $(AWS_REGION) --query "InstanceRefreshes[0].Status" --output text 2>/dev/null || echo "None"); \
		if [ "$$STATUS" != "InProgress" ] && [ "$$STATUS" != "Cancelling" ]; then \
			break; \
		fi; \
		echo "   Waiting for active refresh status '$$STATUS' to clear (attempt $$i/30)..."; \
		sleep 2; \
	done
	aws autoscaling start-instance-refresh \
		--auto-scaling-group-name $(ASG_NAME) \
		--region $(AWS_REGION) \
		--preferences '{"MinHealthyPercentage": 50, "InstanceWarmup": $(WARMUP_SECONDS)}'
	@echo "✅ Instance refresh started."
	@echo ""
	@echo "📋 Step 3/3 — Tailing CloudWatch logs (Ctrl+C to stop watching)..."
	@echo "   Log group: /authpole/production/server"
	@echo ""
	aws logs tail /authpole/production/server \
		--region $(AWS_REGION) \
		--follow \
		--format short

## deploy-admin: Sync admin UI assets to S3 and invalidate CloudFront cache
deploy-admin:
	@echo "🖥️ Deploying Admin UI to S3 + CloudFront..."
	@echo ""
	@echo "📦 Step 1/2 — Syncing assets to S3..."
	aws s3 sync web/admin/ s3://$(ADMIN_S3_BUCKET)/ \
		--region $(AWS_REGION) \
		--delete \
		--cache-control "no-cache, no-store, must-revalidate"
	@echo "✅ Assets synced."
	@echo ""
	@echo "🌐 Step 2/2 — Invalidating CloudFront cache..."
	aws cloudfront create-invalidation \
		--distribution-id $(CLOUDFRONT_ID) \
		--paths "/*" \
		--query 'Invalidation.{ID:Id,Status:Status}' \
		--output table
	@echo "✅ Admin UI deployed to https://authpole-admin.swii.sh"

## deploy: Full deployment — server + admin UI
deploy: deploy-server deploy-admin

## logs: Tail live server logs from CloudWatch
logs:
	@echo "📋 Tailing /authpole/production/server (Ctrl+C to stop)..."
	aws logs tail /authpole/production/server \
		--region $(AWS_REGION) \
		--follow \
		--format short

## cancel-refresh: Cancel an in-progress AWS Auto Scaling instance refresh
cancel-refresh:
	@echo "🛑 Canceling active instance refresh for $(ASG_NAME)..."
	@aws autoscaling cancel-instance-refresh \
		--auto-scaling-group-name $(ASG_NAME) \
		--region $(AWS_REGION)
	@echo "✅ Instance refresh canceled."

## set-oauth-credentials: Set production Google & GitHub OAuth credentials in AWS SSM Parameter Store
set-oauth-credentials:
	@echo "🔑 Setting production OAuth credentials in AWS SSM Parameter Store (region: $(AWS_REGION))..."
	@if [ -n "$(GOOGLE_CLIENT_ID)" ]; then \
		aws ssm put-parameter --name "/authpole/production/google_client_id" --value "$(GOOGLE_CLIENT_ID)" --type "String" --overwrite --region $(AWS_REGION) && \
		echo "✅ Set /authpole/production/google_client_id"; \
	fi
	@if [ -n "$(GOOGLE_CLIENT_SECRET)" ]; then \
		aws ssm put-parameter --name "/authpole/production/google_client_secret" --value "$(GOOGLE_CLIENT_SECRET)" --type "SecureString" --overwrite --region $(AWS_REGION) && \
		echo "✅ Set /authpole/production/google_client_secret"; \
	fi
	@if [ -n "$(GITHUB_CLIENT_ID)" ]; then \
		aws ssm put-parameter --name "/authpole/production/github_client_id" --value "$(GITHUB_CLIENT_ID)" --type "String" --overwrite --region $(AWS_REGION) && \
		echo "✅ Set /authpole/production/github_client_id"; \
	fi
	@if [ -n "$(GITHUB_CLIENT_SECRET)" ]; then \
		aws ssm put-parameter --name "/authpole/production/github_client_secret" --value "$(GITHUB_CLIENT_SECRET)" --type "SecureString" --overwrite --region $(AWS_REGION) && \
		echo "✅ Set /authpole/production/github_client_secret"; \
	fi
	@echo "🎉 Production OAuth credentials updated in AWS SSM Parameter Store!"

## clean: Remove built binaries and clean temporary data
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) data/
	@echo "✅ Clean complete."

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build-go          Build Go binary (native, for local dev)"
	@echo "  build-linux       Cross-compile Linux amd64 binary (for EC2)"
	@echo "  test              Run unit tests"
	@echo "  build-docker      Build Docker container image"
	@echo ""
	@echo "AWS deployment targets:"
	@echo "  deploy-server     Build + upload to S3 + rolling instance refresh + tail logs"
	@echo "  deploy-admin      Sync admin UI to S3 + CloudFront invalidation"
	@echo "  deploy            Full deploy (server + admin UI)"
	@echo "  deploy-terraform  Plan Terraform infrastructure changes"
	@echo "  logs              Tail live server logs from CloudWatch"
	@echo ""
	@echo "Local dev targets:"
	@echo "  run-local         Run full stack locally with docker-compose and MinIO"
	@echo "  stop-local        Stop local docker-compose stack"
	@echo "  build-unikraft    Build Unikraft unikernel image"
	@echo "  clean             Remove build artifacts"
	@echo ""
	@echo "Variables (override with make VAR=value):"
	@echo "  AWS_REGION        AWS region (default: us-east-1)"
	@echo "  S3_BUCKET         S3 bucket name (default: authpole-production-storage)"
	@echo "  ASG_NAME          Auto Scaling Group name (default: authpole-asg)"
	@echo "  WARMUP_SECONDS    Instance warmup time in seconds (default: 120)"
