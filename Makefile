# Authpole Master Makefile

.PHONY: all build build-go test build-docker run-local stop-local build-unikraft deploy-terraform clean help

BINARY_NAME=authpole
BUILD_DIR=bin
DOCKER_IMAGE=authpole:latest
KRAFT_TARGET=qemu/x86_64

all: build-go test

## build-go: Build Go server binary
build-go:
	@echo "🔨 Building Go binary..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server
	@echo "✅ Binary created at $(BUILD_DIR)/$(BINARY_NAME)"

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
	@cd terraform && \
	if command -v terraform > /dev/null; then \
		terraform init && \
		terraform plan -out=tfplan && \
		echo "Execute 'cd terraform && terraform apply tfplan' to confirm deployment."; \
	else \
		echo "⚠️ Terraform CLI not installed. Please install Terraform (https://terraform.io)."; \
	fi

## clean: Remove built binaries and clean temporary data
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) data/
	@echo "✅ Clean complete."

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build-go          Build Go binary"
	@echo "  test              Run unit tests"
	@echo "  build-docker      Build Docker container image"
	@echo "  run-local         Run full stack locally with docker-compose and MinIO"
	@echo "  stop-local        Stop local docker-compose stack"
	@echo "  build-unikraft    Build Unikraft unikernel image"
	@echo "  deploy-terraform  Initialize and plan AWS deployment with Terraform"
	@echo "  clean             Clean build artifacts"
