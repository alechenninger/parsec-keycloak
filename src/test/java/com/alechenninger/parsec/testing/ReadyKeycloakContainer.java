package com.alechenninger.parsec.testing;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.time.Duration;

/**
 * Keycloak container with a wait strategy that waits for health readiness
 * using the management interface health endpoints, avoiding log coupling.
 * See: https://www.keycloak.org/observability/health
 */
public class ReadyKeycloakContainer extends KeycloakContainer {

    public ReadyKeycloakContainer(String imageName) {
        super(imageName);
    }

    @Override
    protected void configure() {
        super.configure();
        // Enable health endpoints and ensure they're available on the management interface (port 9000)
        this.withEnv("KC_HEALTH_ENABLED", "true")
            .withEnv("KC_HTTP_MANAGEMENT_HEALTH_ENABLED", "true");

        // Expose management port 9000 so the wait strategy can hit it
        this.addExposedPort(9000);

        // Wait for the 'started' health endpoint as readiness signal
        this.waitingFor(
                Wait.forHttp("/health/started")
                        .forPort(9000)
                        .forStatusCode(200)
                        .withReadTimeout(Duration.ofSeconds(15))
                        .withStartupTimeout(Duration.ofMinutes(5))
        );
    }
}
