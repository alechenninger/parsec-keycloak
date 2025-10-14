#!/bin/bash
# Script to run tests with Podman on macOS
# This sets up the DOCKER_HOST environment variable to point to Podman's socket

set -e

# Get the Podman socket path dynamically
PODMAN_SOCKET=$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null)

if [ -z "$PODMAN_SOCKET" ]; then
    echo "Error: Could not get Podman socket path. Is Podman machine running?"
    echo "Try: podman machine start"
    exit 1
fi

# Set DOCKER_HOST to point to Podman
export DOCKER_HOST="unix://${PODMAN_SOCKET}"

# Disable Ryuk for Podman compatibility
export TESTCONTAINERS_RYUK_DISABLED=true

echo "Using Podman socket: $DOCKER_HOST"
echo "Ryuk disabled: $TESTCONTAINERS_RYUK_DISABLED"
echo "Running tests..."

# Run Maven tests
mvn test "$@"

