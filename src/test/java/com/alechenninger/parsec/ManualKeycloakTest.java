package com.alechenninger.parsec;

import com.alechenninger.parsec.testing.TestConfig;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * Runnable class for starting Keycloak with the AgeInfoMapper extension locally.
 * 
 * <p>This starts a Keycloak container and keeps it running for manual testing and debugging.
 * You can set breakpoints and use the debugger while manually interacting with Keycloak.</p>
 * 
 * <h3>Usage:</h3>
 * <ol>
 *   <li>Run this class from your IDE (right-click -> Run 'ManualKeycloakTest.main()')</li>
 *   <li>Wait for the container to start and the URLs to be printed</li>
 *   <li>Open the Keycloak admin console in your browser</li>
 *   <li>Log in with the credentials shown in the console</li>
 *   <li>Interact with Keycloak and test your extension</li>
 *   <li>Press Enter in the console to stop the container</li>
 * </ol>
 * 
 * <p>Or run from command line:</p>
 * <pre>mvn test-compile exec:java -Dexec.classpathScope=test -Dexec.mainClass=com.alechenninger.parsec.ManualKeycloakTest</pre>
 */
public class ManualKeycloakTest {

    private static final String TEST_REALM = "master";
    private static final String TEST_CLIENT = "test-client";
    private static final String TEST_USER = "testuser";
    private static final String TEST_PASSWORD = "password";

    public static void main(String[] args) throws Exception {
        System.out.println("========================================");
        System.out.println("Starting Keycloak Container...");
        System.out.println("========================================");
        System.out.println();

        // Create and start the Keycloak container (configured via TestConfig)
        @SuppressWarnings("resource")
        KeycloakContainer keycloak = TestConfig.createKeycloakContainer();
        
        keycloak.start();

        try {
            System.out.println("✓ Keycloak container started successfully!");
            System.out.println();
            
            printConnectionInfo(keycloak);
            
            // Setup a test environment with the AgeInfoMapper configured
            setupTestEnvironment(keycloak);

            System.out.println();
            System.out.println("========================================");
            System.out.println("Container is ready for manual testing!");
            System.out.println("========================================");
            System.out.println();
            System.out.println("You can now:");
            System.out.println("  1. Open the Keycloak admin console in your browser");
            System.out.println("  2. Explore the test client configuration in the master realm");
            System.out.println("  3. Test the AgeInfoMapper with the test user");
            System.out.println("  4. Set breakpoints in your extension code and debug");
            System.out.println();
            System.out.println("Press Enter to stop the container and exit...");
            System.out.println();

            // Wait for user input
            try (Scanner scanner = new Scanner(System.in)) {
                scanner.nextLine();
            }

            System.out.println();
            System.out.println("Stopping Keycloak container...");
        } finally {
            keycloak.stop();
            System.out.println("✓ Container stopped");
        }
    }

    private static void printConnectionInfo(KeycloakContainer keycloak) {
        System.out.println("📋 Connection Information:");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println();
        System.out.println("  Keycloak URL:     " + keycloak.getAuthServerUrl());
        System.out.println("  Admin Console:    " + keycloak.getAuthServerUrl() + "/admin/");
        System.out.println();
        System.out.println("  Admin Username:   " + keycloak.getAdminUsername());
        System.out.println("  Admin Password:   " + keycloak.getAdminPassword());
        System.out.println();
        System.out.println("  Test Realm:       " + TEST_REALM);
        System.out.println("  Test Client:      " + TEST_CLIENT);
        System.out.println("  Test User:        " + TEST_USER + " / " + TEST_PASSWORD);
        System.out.println();
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    private static void setupTestEnvironment(KeycloakContainer keycloak) {
        System.out.println();
        System.out.println("⚙️  Setting up test environment...");
        System.out.println();

        Keycloak adminClient = keycloak.getKeycloakAdminClient();

        // Using the master realm (it always exists)
        System.out.println("  Using realm: " + TEST_REALM);

        // Verify the extension is loaded
        var serverInfo = adminClient.serverInfo().getInfo();
        var protocolMapperSpi = serverInfo.getProviders().get("protocol-mapper");
        if (protocolMapperSpi != null && protocolMapperSpi.getProviders().containsKey(AgeInfoMapper.PROVIDER_ID)) {
            System.out.println("  ✓ AgeInfoMapper extension is loaded");
        }

        // Create a test client with the AgeInfoMapper configured
        System.out.println("  Creating test client: " + TEST_CLIENT);
        var existingClients = adminClient.realm(TEST_REALM).clients().findByClientId(TEST_CLIENT);
        
        if (existingClients.isEmpty()) {
            ClientRepresentation client = new ClientRepresentation();
            client.setClientId(TEST_CLIENT);
            client.setEnabled(true);
            client.setPublicClient(true);
            client.setDirectAccessGrantsEnabled(true);
            client.setStandardFlowEnabled(true);
            client.setRedirectUris(List.of("*"));
            client.setWebOrigins(List.of("*"));
            
            adminClient.realm(TEST_REALM).clients().create(client);
            existingClients = adminClient.realm(TEST_REALM).clients().findByClientId(TEST_CLIENT);
        } else {
            System.out.println("  (Client already exists, reusing)");
        }

        // Add the AgeInfoMapper to the client
        if (!existingClients.isEmpty()) {
            String clientUuid = existingClients.get(0).getId();
            var clientResource = adminClient.realm(TEST_REALM).clients().get(clientUuid);

            var existingMappers = clientResource.getProtocolMappers().getMappers();
            boolean hasAgeMapper = existingMappers.stream()
                    .anyMatch(m -> "age-info-mapper".equals(m.getName()));
            
            if (!hasAgeMapper) {
                System.out.println("  Adding AgeInfoMapper to client");
                ProtocolMapperRepresentation mapperConfig = new ProtocolMapperRepresentation();
                mapperConfig.setName("age-info-mapper");
                mapperConfig.setProtocol("openid-connect");
                mapperConfig.setProtocolMapper(AgeInfoMapper.PROVIDER_ID);
                mapperConfig.setConfig(Map.of(
                        "access.token.claim", "true",
                        "id.token.claim", "true",
                        "userinfo.token.claim", "true"
                ));
                
                clientResource.getProtocolMappers().createMapper(mapperConfig);
            } else {
                System.out.println("  (AgeInfoMapper already configured)");
            }
        }

        // Create a test user with a birthdate
        System.out.println("  Creating test user: " + TEST_USER);
        var existingUsers = adminClient.realm(TEST_REALM).users().search(TEST_USER, true);
        
        if (existingUsers.isEmpty()) {
            UserRepresentation user = new UserRepresentation();
            user.setUsername(TEST_USER);
            user.setEnabled(true);
            user.setEmail("testuser@example.com");
            user.setFirstName("Test");
            user.setLastName("User");
            user.setAttributes(Map.of("birthdate", List.of("1990-01-01")));
            
            // Set password as part of user creation
            CredentialRepresentation passwordCred = new CredentialRepresentation();
            passwordCred.setType(CredentialRepresentation.PASSWORD);
            passwordCred.setValue(TEST_PASSWORD);
            passwordCred.setTemporary(false);
            user.setCredentials(List.of(passwordCred));
            
            adminClient.realm(TEST_REALM).users().create(user);
        } else {
            System.out.println("  (User already exists, reusing)");
        }

        System.out.println();
        System.out.println("✓ Test environment setup complete!");
        System.out.println();
        System.out.println("  To test the AgeInfoMapper:");
        System.out.println("  1. Go to: " + keycloak.getAuthServerUrl() + "/realms/" + TEST_REALM + "/account/");
        System.out.println("  2. Login with: " + TEST_USER + " / " + TEST_PASSWORD);
        System.out.println();
        System.out.println("  Or get tokens via Direct Access Grant:");
        System.out.println("  POST " + keycloak.getAuthServerUrl() + "/realms/" + TEST_REALM + "/protocol/openid-connect/token");
        System.out.println("  Body: grant_type=password&client_id=" + TEST_CLIENT + "&username=" + TEST_USER + "&password=" + TEST_PASSWORD);
    }
}

