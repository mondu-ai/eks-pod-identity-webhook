# EKS Pod Identity Webhook Makefile

# Variables
APP_NAME := eks-pod-identity-webhook

# Test flags
TEST_FLAGS := -v -race -timeout=30s
COVERAGE_FILE := coverage.out

.PHONY: all test lint clean help

# Default target
all: lint test

# Help target
help: ## Show this help message
	@echo "EKS Pod Identity Webhook - Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Install dependencies
deps: ## Download and verify dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod verify
	go mod tidy

# Run tests
test: ## Run tests
	@echo "Running tests..."
	go test $(TEST_FLAGS) ./...

# Run tests with coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test $(TEST_FLAGS) -coverprofile=$(COVERAGE_FILE) ./...
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Lint the code
lint: ## Run linter
	@echo "Running linter..."
	@which golangci-lint >/dev/null 2>&1 || { \
		echo "Installing golangci-lint v2.1.6..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6; \
	}
	golangci-lint run ./...

# Format the code
fmt: ## Format Go code
	@echo "Formatting code..."
	go fmt ./...
	@command -v goimports >/dev/null 2>&1 || { \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	}
	goimports -w .

# Vet the code
vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

# Security scan
security: ## Run security scan with gosec
	@echo "Running security scan..."
	@command -v gosec >/dev/null 2>&1 || { \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	}
	gosec -fmt sarif -out results.sarif ./...

# Clean build artifacts
clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(COVERAGE_FILE) coverage.html results.sarif

# Check for updates
check-updates: ## Check for dependency updates
	@echo "Checking for dependency updates..."
	go list -u -m all

# Update dependencies
update-deps: ## Update all dependencies to latest versions
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "Dependencies updated!"

# Full CI pipeline
ci: deps fmt vet lint security test ## Run full CI pipeline
