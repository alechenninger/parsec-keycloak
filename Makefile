.PHONY: help clean compile build-deps test test-integration package

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

clean: ## Clean build artifacts
	mvn clean

compile: ## Compile the code
	mvn compile test-compile

build-deps: ## Build the dependencies JAR (target/parsec-dependencies.jar)
	mvn package -DskipTests

test: compile build-deps ## Run all tests
	mvn test

test-integration: compile build-deps ## Run integration tests only
	mvn test -Dtest=*IntegrationTest

package: ## Build JAR package
	mvn package

# Quick test cycle: only recompile and run tests (assumes dependencies JAR already built)
quick-test: compile ## Quick test without rebuilding dependencies JAR
	mvn test

