# Testcontainers with Podman

This project uses Testcontainers for integration testing with Keycloak. On macOS, we use Podman instead of Docker Desktop.

## Setup

### 1. Ensure Podman is Running

```bash
podman machine start
```

### 2. Configure Environment for Tests

You have several options depending on how you run tests:

#### Option A: Running Tests in Cursor/VS Code (Recommended for IDE)

The `.vscode/settings.json` file contains the `DOCKER_HOST` environment variable that points to your Podman socket.

**Important:** If your Podman socket path changes (e.g., after restarting your machine), run:

```bash
./update-podman-settings.sh
```

Then reload the Cursor/VS Code window:
- Press `Cmd+Shift+P`
- Type "Developer: Reload Window"

#### Option B: Running Tests from Terminal with Maven

Set the `DOCKER_HOST` environment variable before running tests:

```bash
# Option 1: Export directly
export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"
mvn test

# Option 2: Use the helper script
./test-with-podman.sh

# Option 3: Source the .envrc file
source .envrc
mvn test
```

#### Option C: Using direnv (For Automatic Environment Setup)

If you use [direnv](https://direnv.net/), the `.envrc` file will automatically set the `DOCKER_HOST` variable whenever you `cd` into this directory:

```bash
# Install direnv if you haven't already
brew install direnv

# Allow direnv for this project
direnv allow

# Now DOCKER_HOST will be set automatically when you enter this directory
```

## Configuration Files

- **`.vscode/settings.json`**: Sets `DOCKER_HOST` and `TESTCONTAINERS_RYUK_DISABLED` for Java test runner in IDE
- **`src/test/resources/testcontainers.properties`**: Configures Testcontainers behavior (reuse, ryuk disabled)
- **`pom.xml`**: Maven Surefire plugin passes through environment variables for Podman
- **`.envrc`**: Shell environment configuration (optional, for direnv or manual sourcing)

## Troubleshooting

### Tests fail with "Could not find a valid Docker environment"

1. Check if Podman is running: `podman machine list`
2. Verify the socket exists: `ls -l $(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')`
3. Update VS Code settings: `./update-podman-settings.sh`
4. Reload Cursor/VS Code window

### Socket path changes

The Podman socket path can change between machine restarts. If tests suddenly stop working:

```bash
./update-podman-settings.sh
```

Then reload your IDE window.

## Why These Settings?

- **`TESTCONTAINERS_RYUK_DISABLED=true`**: Ryuk (cleanup container) doesn't work well with Podman on macOS due to socket mounting issues
- **`testcontainers.reuse.enable=true`**: Reuses containers between test runs for faster execution  
- **`DOCKER_HOST`**: Tells Testcontainers where to find the container runtime (Podman's socket)

**Note:** We set Ryuk disabled both in `testcontainers.properties` and as an environment variable for maximum compatibility.

