#!/bin/bash
# Updates .vscode/settings.json with the current Podman socket path
# Run this script whenever your Podman socket path changes

set -e

PODMAN_SOCKET=$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null)

if [ -z "$PODMAN_SOCKET" ]; then
    echo "Error: Could not get Podman socket path. Is Podman machine running?"
    echo "Try: podman machine start"
    exit 1
fi

DOCKER_HOST="unix://${PODMAN_SOCKET}"

echo "Updating .vscode/settings.json with DOCKER_HOST: $DOCKER_HOST"

# Use jq if available, otherwise use sed
if command -v jq &> /dev/null; then
    # Using jq for clean JSON manipulation
    jq --arg host "$DOCKER_HOST" \
       '.["java.test.config"].env.DOCKER_HOST = $host | .["java.test.config"].env.TESTCONTAINERS_RYUK_DISABLED = "true"' \
       .vscode/settings.json > .vscode/settings.json.tmp
    mv .vscode/settings.json.tmp .vscode/settings.json
    echo "✓ Settings updated successfully"
else
    # Fallback to sed
    sed -i.bak "s|\"DOCKER_HOST\": \".*\"|\"DOCKER_HOST\": \"$DOCKER_HOST\"|" .vscode/settings.json
    rm -f .vscode/settings.json.bak
    echo "✓ Settings updated successfully (using sed)"
fi

echo ""
echo "You may need to reload the window in Cursor/VS Code for changes to take effect."
echo "Command Palette (Cmd+Shift+P) -> 'Developer: Reload Window'"

