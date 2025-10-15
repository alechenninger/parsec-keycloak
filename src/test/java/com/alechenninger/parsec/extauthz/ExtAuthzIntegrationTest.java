package com.alechenninger.parsec.extauthz;

import com.alechenninger.parsec.testing.TestConfig;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.service.auth.v3.AttributeContext;
import io.envoyproxy.envoy.service.auth.v3.AuthorizationGrpc;
import io.envoyproxy.envoy.service.auth.v3.CheckRequest;
import io.envoyproxy.envoy.service.auth.v3.CheckResponse;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for ExtAuthzService running within a Keycloak container.
 * 
 * This test verifies that:
 * 1. The gRPC server starts successfully within Keycloak
 * 2. The ext_authz protocol is correctly implemented
 * 3. Envoy can communicate with the service
 */
@Testcontainers
class ExtAuthzIntegrationTest {
    
    @Container
    static KeycloakContainer keycloak = TestConfig.createKeycloakContainer()
        // Configure the ext_authz server SPI via environment variables
        // Format: KC_SPI_<spi-name>_<provider-id>_<property>
        // SPI name: ext-authz-server, Provider ID: ext-authz-server
        .withEnv("KC_SPI_EXT_AUTHZ_SERVER_EXT_AUTHZ_SERVER_PORT", "9191")
        .withEnv("KC_SPI_EXT_AUTHZ_SERVER_EXT_AUTHZ_SERVER_HOST", "0.0.0.0")
        .withEnv("KC_SPI_EXT_AUTHZ_SERVER_EXT_AUTHZ_SERVER_AUTO_START", "true")
        .withEnv("KC_LOG_LEVEL", "INFO,com.alechenninger.parsec:DEBUG");
        // Note: gRPC port 9191 is exposed via ReadyKeycloakContainer.configure()
    
    private static ManagedChannel grpcChannel;
    private static AuthorizationGrpc.AuthorizationBlockingStub authzStub;
    
    @BeforeAll
    static void setUp() throws InterruptedException {
        // Wait for Keycloak to be ready
        keycloak.start();
        
        // Print container logs for debugging
        System.out.println("=== Keycloak Container Logs ===");
        System.out.println(keycloak.getLogs());
        System.out.println("=== End Logs ===");
        
        // Get the gRPC port mapping
        Integer grpcPort = keycloak.getMappedPort(9191);
        String grpcHost = keycloak.getHost();
        
        System.out.println("Connecting to ext_authz gRPC service at " + grpcHost + ":" + grpcPort);
        
        // Give the gRPC server a moment to start after Keycloak is ready
        Thread.sleep(2000);
        
        // Create gRPC channel
        grpcChannel = ManagedChannelBuilder
            .forAddress(grpcHost, grpcPort)
            .usePlaintext()
            .build();
        
        authzStub = AuthorizationGrpc.newBlockingStub(grpcChannel);
    }
    
    @AfterAll
    static void tearDown() throws InterruptedException {
        if (grpcChannel != null) {
            grpcChannel.shutdown();
            grpcChannel.awaitTermination(5, TimeUnit.SECONDS);
        }
    }
    
    @Test
    void testExtAuthzServiceRespondsToCheckRequest() {
        // Given: A check request simulating an Envoy authorization check
        CheckRequest request = CheckRequest.newBuilder()
            .setAttributes(
                AttributeContext.newBuilder()
                    .setRequest(
                        AttributeContext.Request.newBuilder()
                            .setHttp(
                                AttributeContext.HttpRequest.newBuilder()
                                    .setMethod("GET")
                                    .setPath("/api/resource")
                                    .setHost("example.com")
                                    .setScheme("https")
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build();
        
        // When: We call the check method
        CheckResponse response = authzStub.check(request);
        
        // Then: The response should be OK (POC implementation)
        assertThat(response).isNotNull();
        assertThat(response.hasOkResponse())
            .withFailMessage("Expected OK response, got: " + response)
            .isTrue();
        
        // Verify the POC header is present
        boolean foundHeader = false;
        for (var headerOption : response.getOkResponse().getHeadersList()) {
            HeaderValue header = headerOption.getHeader();
            System.out.println("Response header: " + header.getKey() + " = " + header.getValue());
            if ("x-parsec-status".equals(header.getKey()) && 
                "poc-success".equals(header.getValue())) {
                foundHeader = true;
            }
        }
        
        assertThat(foundHeader)
            .withFailMessage("Expected to find x-parsec-status: poc-success header")
            .isTrue();
    }
    
    @Test
    void testExtAuthzServiceWithAuthorizationHeader() {
        // Given: A check request with an authorization header
        CheckRequest request = CheckRequest.newBuilder()
            .setAttributes(
                AttributeContext.newBuilder()
                    .setRequest(
                        AttributeContext.Request.newBuilder()
                            .setHttp(
                                AttributeContext.HttpRequest.newBuilder()
                                    .setMethod("POST")
                                    .setPath("/api/protected/resource")
                                    .setHost("api.example.com")
                                    .setScheme("https")
                                    .putHeaders("authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
                                    .putHeaders("content-type", "application/json")
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build();
        
        // When: We call the check method
        CheckResponse response = authzStub.check(request);
        
        // Then: Should still return OK (token validation will come in later phases)
        assertThat(response).isNotNull();
        assertThat(response.hasOkResponse()).isTrue();
    }
    
    @Test
    void testMultipleSequentialRequests() {
        // Test that the service can handle multiple requests
        for (int i = 0; i < 5; i++) {
            CheckRequest request = CheckRequest.newBuilder()
                .setAttributes(
                    AttributeContext.newBuilder()
                        .setRequest(
                            AttributeContext.Request.newBuilder()
                                .setHttp(
                                    AttributeContext.HttpRequest.newBuilder()
                                        .setMethod("GET")
                                        .setPath("/api/test/" + i)
                                        .setHost("example.com")
                                        .build()
                                )
                                .build()
                        )
                        .build()
                )
                .build();
            
            CheckResponse response = authzStub.check(request);
            assertThat(response.hasOkResponse()).isTrue();
        }
    }
}

