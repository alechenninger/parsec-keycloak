package com.alechenninger.parsec;

import static org.assertj.core.api.Assertions.assertThat;

import com.alechenninger.parsec.testing.TestConfig;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.info.ProviderRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import dasniko.testcontainers.keycloak.KeycloakContainer;

import java.util.List;
import java.util.Map;

/**
 * Integration tests for custom Keycloak protocol mappers.
 */
@Testcontainers
public class AgeInfoMapperTest {

    @SuppressWarnings("resource")
    @Container
    private static final KeycloakContainer keycloak = TestConfig.createKeycloakContainer();

    /**
     * Test that the AgeInfoMapper extension is loaded and available in the Keycloak container.
     */
    @Test
    public void testAgeInfoMapperIsLoadedAndAvailable() {
        // Get the Keycloak admin client
        Keycloak adminClient = keycloak.getKeycloakAdminClient();
        
        // Get server info which includes all available protocol mappers
        ServerInfoRepresentation serverInfo = adminClient.serverInfo().getInfo();
        
        // Get the protocol mapper providers
        var protocolMapperSpi = serverInfo.getProviders().get("protocol-mapper");
        
        assertThat(protocolMapperSpi)
                .as("Protocol mapper SPI should be available")
                .isNotNull();
        
        Map<String, ProviderRepresentation> protocolMapperProviders = protocolMapperSpi.getProviders();
        
        assertThat(protocolMapperProviders)
                .as("Protocol mapper providers should be available")
                .isNotNull()
                .isNotEmpty();
        
        // Verify that our custom AgeInfoMapper is registered
        assertThat(protocolMapperProviders)
                .as("AgeInfoMapper should be registered with provider ID: " + AgeInfoMapper.PROVIDER_ID)
                .containsKey(AgeInfoMapper.PROVIDER_ID);
        
        ProviderRepresentation ageInfoMapperProvider = protocolMapperProviders.get(AgeInfoMapper.PROVIDER_ID);
        
        assertThat(ageInfoMapperProvider)
                .as("AgeInfoMapper provider details should be available")
                .isNotNull();
        
        System.out.println("✓ AgeInfoMapper successfully loaded in Keycloak container");
        System.out.println("  Provider ID: " + AgeInfoMapper.PROVIDER_ID);
        System.out.println("  Provider Details: " + ageInfoMapperProvider);
    }
    
    /**
     * Test that the AgeInfoMapper can be added to a client configuration.
     * This test uses an existing client to avoid timing/consistency issues with client creation.
     */
    @Test
    public void testAgeInfoMapperCanBeAddedToClient() {
        Keycloak adminClient = keycloak.getKeycloakAdminClient();
        String testRealm = "master";
        
        // Use an existing client (like the admin-cli or account client) 
        // to verify we can add our custom mapper
        var clientsResource = adminClient.realm(testRealm).clients();
        var existingClients = clientsResource.findByClientId("admin-cli");
        
        assertThat(existingClients)
                .as("admin-cli client should exist in master realm")
                .isNotEmpty();
        
        String clientUuid = existingClients.get(0).getId();
        var clientResource = clientsResource.get(clientUuid);
        
        // Store original mappers to restore later
        List<ProtocolMapperRepresentation> originalMappers = clientResource.getProtocolMappers().getMappers();
        
        try {
            // Create a protocol mapper configuration for our custom mapper
            ProtocolMapperRepresentation mapperConfig = new ProtocolMapperRepresentation();
            mapperConfig.setName("test-age-info-mapper");
            mapperConfig.setProtocol("openid-connect");
            mapperConfig.setProtocolMapper(AgeInfoMapper.PROVIDER_ID);
            
            // Configure the mapper to be included in access token, id token, and userinfo
            Map<String, String> config = Map.of(
                    "access.token.claim", "true",
                    "id.token.claim", "true",
                    "userinfo.token.claim", "true"
            );
            mapperConfig.setConfig(config);
            
            // Add the mapper to the client
            clientResource.getProtocolMappers().createMapper(mapperConfig);
            
            // Verify the mapper was added
            List<ProtocolMapperRepresentation> mappers = clientResource.getProtocolMappers().getMappers();
            
            assertThat(mappers)
                    .as("Client should have protocol mappers")
                    .isNotNull()
                    .hasSizeGreaterThan(originalMappers.size());
            
            assertThat(mappers)
                    .as("Client should have our custom AgeInfoMapper configured")
                    .anyMatch(m -> AgeInfoMapper.PROVIDER_ID.equals(m.getProtocolMapper()));
            
            System.out.println("✓ AgeInfoMapper successfully added to client configuration");
            System.out.println("  Client: admin-cli");
            System.out.println("  Mapper Name: test-age-info-mapper");
            
            // Find and remove the test mapper
            mappers.stream()
                    .filter(m -> "test-age-info-mapper".equals(m.getName()))
                    .findFirst()
                    .ifPresent(m -> clientResource.getProtocolMappers().delete(m.getId()));
            
        } catch (Exception e) {
            // Best effort cleanup on error
            try {
                List<ProtocolMapperRepresentation> mappers = clientResource.getProtocolMappers().getMappers();
                mappers.stream()
                        .filter(m -> "test-age-info-mapper".equals(m.getName()))
                        .findFirst()
                        .ifPresent(m -> clientResource.getProtocolMappers().delete(m.getId()));
            } catch (Exception cleanupEx) {
                // Ignore cleanup errors
            }
            throw e;
        }
    }
}
