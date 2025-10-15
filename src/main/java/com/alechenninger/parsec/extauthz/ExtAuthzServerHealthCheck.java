package com.alechenninger.parsec.extauthz;

import io.smallrye.health.api.AsyncHealthCheck;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Startup;
import org.jboss.logging.Logger;

/**
 * Health check for the ext_authz gRPC server.
 * 
 * This check verifies that the gRPC server has been started and is ready to accept connections.
 * It's marked as @Readiness so it affects the /health/ready endpoint.
 */
@Startup
@ApplicationScoped
public class ExtAuthzServerHealthCheck implements AsyncHealthCheck {
    
    private static final Logger logger = Logger.getLogger(ExtAuthzServerHealthCheck.class);
    
    @Override
    public Uni<HealthCheckResponse> call() {
        return Uni.createFrom().item(() -> {
            HealthCheckResponseBuilder builder = HealthCheckResponse.named("ext-authz-grpc-server");
            
            try {
                // Check the server status directly from the implementation
                boolean isRunning = ExtAuthzServerProviderImpl.isServerRunning();
                int port = ExtAuthzServerProviderImpl.getServerPort();
                
                if (isRunning && port > 0) {
                    logger.debug("ext_authz gRPC server is running on port " + port);
                    return builder
                        .up()
                        .withData("port", port)
                        .withData("status", "running")
                        .build();
                } else {
                    logger.debug("ext_authz gRPC server is not running");
                    return builder
                        .down()
                        .withData("reason", "gRPC server not started")
                        .build();
                }
                
            } catch (Exception e) {
                logger.error("Error checking ext_authz gRPC server health", e);
                return builder
                    .down()
                    .withData("error", e.getMessage())
                    .build();
            }
        });
    }
}

