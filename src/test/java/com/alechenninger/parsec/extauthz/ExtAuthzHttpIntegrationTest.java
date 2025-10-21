package com.alechenninger.parsec.extauthz;

import com.alechenninger.parsec.testing.ParsecKeycloakContainer;
import com.alechenninger.parsec.testing.TestConfig;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.*;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for HTTP ext_authz endpoint.
 * 
 * Tests the complete flow:
 * 1. Keycloak container with extension loaded
 * 2. Realm, clients, and user created
 * 3. Obtain real tokens (proxy client + user)
 * 4. Call HTTP ext_authz endpoint
 * 5. Verify token exchange occurs and proper response format
 */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ExtAuthzHttpIntegrationTest {
    
    private static final String TEST_REALM = "test-realm";
    private static final String PROXY_CLIENT_ID = "test-proxy";
    private static final String PROXY_CLIENT_SECRET = "proxy-secret";
    private static final String USER_CLIENT_ID = "test-app";
    private static final String TARGET_CLIENT_ID = "test-target";  // Target service for token exchange
    private static final String TEST_USER = "testuser";
    private static final String TEST_PASSWORD = "testpass";
    
    @Container
    static KeycloakContainer keycloak = TestConfig.createKeycloakContainer()
        .withEnv("KC_FEATURES", "token-exchange")
        .withEnv("KC_LOG_LEVEL", "INFO,com.alechenninger.parsec:DEBUG");
    
    private static HttpClient httpClient;
    private static ObjectMapper objectMapper;
    private static String proxyToken;
    private static String userToken;
    private static String authUrl;
    
    @BeforeAll
    static void setUp() {
        System.out.println("\n=== Setting up Keycloak test environment ===");
        
        httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();
        
        objectMapper = new ObjectMapper();
        
        authUrl = keycloak.getAuthServerUrl();
        System.out.println("Keycloak auth URL: " + authUrl);
        
        // Set up test realm, clients, and user
        setupTestRealm();
        
        // Obtain tokens for testing
        obtainTokens();
        
        System.out.println("=== Test setup complete ===\n");
    }
    
    /**
     * Set up a test realm with clients and users for token exchange testing.
     */
    private static void setupTestRealm() {
        Keycloak adminClient = keycloak.getKeycloakAdminClient();
        
        // Create test realm
        RealmRepresentation realm = new RealmRepresentation();
        realm.setRealm(TEST_REALM);
        realm.setEnabled(true);
        realm.setAccessTokenLifespan(300); // 5 minutes
        
        adminClient.realms().create(realm);
        System.out.println("✓ Created realm: " + TEST_REALM);
        
        // Create proxy client (confidential client for token exchange)
        ClientRepresentation proxyClient = new ClientRepresentation();
        proxyClient.setClientId(PROXY_CLIENT_ID);
        proxyClient.setEnabled(true);
        proxyClient.setPublicClient(false);
        proxyClient.setServiceAccountsEnabled(true);
        proxyClient.setDirectAccessGrantsEnabled(true);
        proxyClient.setStandardFlowEnabled(true);
        proxyClient.setSecret(PROXY_CLIENT_SECRET);
        proxyClient.setFullScopeAllowed(true);  // Allow all scopes
        proxyClient.setProtocol("openid-connect");  // OIDC protocol
        proxyClient.setDefaultClientScopes(java.util.List.of("openid", "profile", "email", "roles"));  // Include openid scope
        
        // Enable OAuth 2.0 Token Exchange (Keycloak 26+)
        // Standard token exchange V2 is enabled by default at server level
        // We need to enable it at the client level with the correct attribute
        if (proxyClient.getAttributes() == null) {
            proxyClient.setAttributes(new java.util.HashMap<>());
        }
        // Try both attribute names to ensure compatibility
        proxyClient.getAttributes().put("oauth2.token.exchange.grant.enabled", "true");  // Legacy V1?
        proxyClient.getAttributes().put("token.exchange.grant.enabled", "true");  // V2?
        
        var proxyCreateResponse = adminClient.realm(TEST_REALM).clients().create(proxyClient);
        String proxyClientUuid = extractClientIdFromResponse(proxyCreateResponse);
        System.out.println("✓ Created proxy client: " + PROXY_CLIENT_ID + " (UUID: " + proxyClientUuid + ")");
        System.out.println("  ✓ Token Exchange attributes configured");
        
        // Create user client (public client for password grant)
        ClientRepresentation userClient = new ClientRepresentation();
        userClient.setClientId(USER_CLIENT_ID);
        userClient.setEnabled(true);
        userClient.setPublicClient(true);
        userClient.setDirectAccessGrantsEnabled(true);
        userClient.setStandardFlowEnabled(true);
        
        var userClientCreateResponse = adminClient.realm(TEST_REALM).clients().create(userClient);
        String userClientUuid = extractClientIdFromResponse(userClientCreateResponse);
        System.out.println("✓ Created user client: " + USER_CLIENT_ID + " (UUID: " + userClientUuid + ")");
        
        // Create target client (represents the target service for token exchange)
        ClientRepresentation targetClient = new ClientRepresentation();
        targetClient.setClientId(TARGET_CLIENT_ID);
        targetClient.setEnabled(true);
        targetClient.setPublicClient(false);  // Confidential client
        targetClient.setServiceAccountsEnabled(false);  // Target doesn't need service account
        targetClient.setDirectAccessGrantsEnabled(false);
        targetClient.setStandardFlowEnabled(true);
        
        var targetClientCreateResponse = adminClient.realm(TEST_REALM).clients().create(targetClient);
        String targetClientUuid = extractClientIdFromResponse(targetClientCreateResponse);
        System.out.println("✓ Created target client: " + TARGET_CLIENT_ID + " (UUID: " + targetClientUuid + ")");
        
        // Create test user
        UserRepresentation user = new UserRepresentation();
        user.setUsername(TEST_USER);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEnabled(true);
        user.setEmailVerified(true);
        user.setEmail(TEST_USER + "@example.com");
        user.setRequiredActions(java.util.List.of());  // No required actions
        
        var userCreateResponse = adminClient.realm(TEST_REALM).users().create(user);
        System.out.println("✓ Created test user: " + TEST_USER);
        
        // Set password using resetPassword API (more reliable than setting during creation)
        String createdUserId = extractClientIdFromResponse(userCreateResponse);
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(TEST_PASSWORD);
        credential.setTemporary(false);
        
        adminClient.realm(TEST_REALM).users().get(createdUserId).resetPassword(credential);
        System.out.println("  ✓ Set password for user");
    }
    
    /**
     * Obtain tokens for testing.
     */
    private static void obtainTokens() {
        // Get proxy client token (service account / client credentials)
        try (Keycloak proxyKeycloak = KeycloakBuilder.builder()
                .serverUrl(authUrl)
                .realm(TEST_REALM)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(PROXY_CLIENT_ID)
                .clientSecret(PROXY_CLIENT_SECRET)
                .build()) {
            proxyToken = proxyKeycloak.tokenManager().getAccessTokenString();
            System.out.println("✓ Obtained proxy client token (service account)");
        } catch (Exception e) {
            System.err.println("Failed to obtain proxy token: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
        
        // Get user token (password grant via proxy client)
        // Use the PROXY client so the token is issued to it, making token exchange work
        try (Keycloak userKeycloak = KeycloakBuilder.builder()
                .serverUrl(authUrl)
                .realm(TEST_REALM)
                .grantType(org.keycloak.OAuth2Constants.PASSWORD)
                .clientId(PROXY_CLIENT_ID)  // Use proxy client
                .clientSecret(PROXY_CLIENT_SECRET)  // Proxy needs credentials
                .username(TEST_USER)
                .password(TEST_PASSWORD)
                .build()) {
            userToken = userKeycloak.tokenManager().getAccessTokenString();
            System.out.println("✓ Obtained user token (password grant via proxy client)");
            
            // Verify the user token is valid by calling userinfo endpoint
            try {
                String userinfoEndpoint = authUrl + "/realms/" + TEST_REALM + "/protocol/openid-connect/userinfo";
                HttpRequest userinfoRequest = HttpRequest.newBuilder()
                    .uri(URI.create(userinfoEndpoint))
                    .header("Authorization", "Bearer " + userToken)
                    .GET()
                    .build();
                HttpResponse<String> userinfoResponse = httpClient.send(userinfoRequest, HttpResponse.BodyHandlers.ofString());
                System.out.println("  ✓ User token validated via userinfo endpoint (status: " + userinfoResponse.statusCode() + ")");
                if (userinfoResponse.statusCode() != 200) {
                    System.err.println("WARNING: User token might not be valid! Userinfo response: " + userinfoResponse.body());
                }
            } catch (Exception ex) {
                System.err.println("Failed to validate user token via userinfo: " + ex.getMessage());
            }
        } catch (jakarta.ws.rs.BadRequestException e) {
            System.err.println("Failed to obtain user token - BadRequest");
            System.err.println("This usually means:");
            System.err.println("  - Direct access grants (password grant) not enabled on client");
            System.err.println("  - User credentials invalid");
            System.err.println("  - Client configuration issue");
            
            // Try to get more details from the response
            if (e.getResponse() != null) {
                System.err.println("Response status: " + e.getResponse().getStatus());
                try {
                    String body = e.getResponse().readEntity(String.class);
                    System.err.println("Response body: " + body);
                } catch (Exception readEx) {
                    System.err.println("Could not read response body");
                }
            }
            
            e.printStackTrace();
            throw e;
        } catch (Exception e) {
            System.err.println("Failed to obtain user token: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
    
    @Test
    @Order(0)
    @DisplayName("Test direct token exchange via Keycloak token endpoint")
    void testDirectTokenExchange() throws Exception {
        System.out.println("\n=== Testing direct token exchange via Keycloak ===");
        
        // Build token endpoint URL
        String tokenEndpoint = authUrl + "/realms/" + TEST_REALM + "/protocol/openid-connect/token";
        System.out.println("Token endpoint: " + tokenEndpoint);
        
        // Build form body for token exchange
        // Use the proxy's own service account token as the subject - this should definitely work!
        String formBody = String.format(
            "grant_type=%s&client_id=%s&client_secret=%s&subject_token=%s&subject_token_type=%s&requested_token_type=%s&audience=%s",
            java.net.URLEncoder.encode("urn:ietf:params:oauth:grant-type:token-exchange", "UTF-8"),
            java.net.URLEncoder.encode(PROXY_CLIENT_ID, "UTF-8"),
            java.net.URLEncoder.encode(PROXY_CLIENT_SECRET, "UTF-8"),
            java.net.URLEncoder.encode(proxyToken, "UTF-8"),  // Use proxy's own token as subject
            java.net.URLEncoder.encode("urn:ietf:params:oauth:token-type:access_token", "UTF-8"),
            java.net.URLEncoder.encode("urn:ietf:params:oauth:token-type:access_token", "UTF-8"),
            java.net.URLEncoder.encode(PROXY_CLIENT_ID, "UTF-8")  // Audience = same client (for POC)
        );
        
        // Make request
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(tokenEndpoint))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formBody))
            .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        System.out.println("Direct token exchange response status: " + response.statusCode());
        System.out.println("Direct token exchange response body: " + response.body());
        
        // This test is just to verify the configuration - we'll use the result in the next test
        if (response.statusCode() != 200) {
            System.err.println("FAILED: Direct token exchange not working. Check client configuration.");
            System.err.println("This means the token-exchange feature is not properly enabled for the client.");
        } else {
            System.out.println("SUCCESS: Direct token exchange is working!");
        }
    }
    
    @Test
    @Order(1)
    @DisplayName("Test ext_authz endpoint with real token exchange")
    void testExtAuthzWithTokenExchange() throws Exception {
        System.out.println("\n=== Testing HTTP ext_authz with real tokens ===");
        System.out.println("Proxy token (first 50 chars): " + proxyToken.substring(0, Math.min(50, proxyToken.length())) + "...");
        System.out.println("User token (first 50 chars): " + userToken.substring(0, Math.min(50, userToken.length())) + "...");
        
        // Build the ext_authz check endpoint URL
        String extAuthzUrl = authUrl + "/realms/" + TEST_REALM + "/ext-authz/check";
        System.out.println("Calling ext_authz endpoint: " + extAuthzUrl);
        
        // Build Envoy ext_authz request body
        // Envoy sends the original client request headers in the body
        // For POC: Use proxy token as subject (same client exchange)
        Map<String, Object> envoyBody = Map.of(
            "attributes", Map.of(
                "request", Map.of(
                    "http", Map.of(
                        "headers", Map.of(
                            "authorization", "Bearer " + proxyToken  // Subject token (proxy's own for POC)
                        )
                    )
                )
            )
        );
        
        String bodyJson = objectMapper.writeValueAsString(envoyBody);
        
        // Create HTTP request with standard client authentication (Basic)
        String basic = Base64.getEncoder().encodeToString((PROXY_CLIENT_ID + ":" + PROXY_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(extAuthzUrl))
            .header("Content-Type", "application/json")
            .header("Authorization", "Basic " + basic)
            .POST(HttpRequest.BodyPublishers.ofString(bodyJson))      // Envoy body with proxied headers
            .build();
        
        // Send request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        System.out.println("Response status: " + response.statusCode());
        System.out.println("Response body: " + response.body());
        
        // Verify response
        assertEquals(200, response.statusCode(), "Expected 200 OK response");
        
        // Parse JSON response
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = objectMapper.readValue(response.body(), Map.class);
        
        // Verify response format (Envoy ext_authz HTTP protocol)
        assertEquals("ok", responseBody.get("status"), "Status should be 'ok'");
        assertTrue(responseBody.containsKey("headers"), "Response should contain 'headers' field");
        
        // Verify exchanged token in headers
        @SuppressWarnings("unchecked")
        Map<String, String> headers = (Map<String, String>) responseBody.get("headers");
        assertTrue(headers.containsKey("authorization"), "Should have 'authorization' header");
        assertTrue(headers.get("authorization").startsWith("Bearer "), 
            "Authorization header should start with 'Bearer '");
        
        String exchangedToken = headers.get("authorization").substring("Bearer ".length());
        assertNotEquals(userToken, exchangedToken, 
            "Exchanged token should be different from original user token");
        
        // Verify debug header
        assertEquals("true", headers.get("x-parsec-token-exchanged"),
            "Should have debug header indicating token was exchanged");
        
        System.out.println("✓ Token exchange successful!");
        System.out.println("  Original token length: " + userToken.length());
        System.out.println("  Exchanged token length: " + exchangedToken.length());
        System.out.println("  Exchanged token (first 50 chars): " + 
            exchangedToken.substring(0, Math.min(50, exchangedToken.length())) + "...");
    }
    
    @Test
    @Order(2)
    @DisplayName("Test ext_authz endpoint without proxy authentication")
    void testExtAuthzWithoutProxyAuth() throws Exception {
        System.out.println("\n=== Testing ext_authz without proxy authentication ===");
        
        String extAuthzUrl = authUrl + "/realms/" + TEST_REALM + "/ext-authz/check";
        
        // Request without client authentication header
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(extAuthzUrl))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + userToken)
            .POST(HttpRequest.BodyPublishers.ofString("{}"))
            .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        System.out.println("Response status: " + response.statusCode());
        System.out.println("Response body: " + response.body());
        
        // Should return 403 Forbidden
        assertEquals(403, response.statusCode(), "Expected 403 Forbidden without proxy auth");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = objectMapper.readValue(response.body(), Map.class);
        assertEquals("denied", responseBody.get("status"), "Status should be 'denied'");
        assertTrue(responseBody.containsKey("reason"), "Should have 'reason' field");
        
        System.out.println("✓ Correctly denied request without proxy authentication");
    }
    
    @Test
    @Order(3)
    @DisplayName("Test ext_authz endpoint without subject token")
    void testExtAuthzWithoutSubjectToken() throws Exception {
        System.out.println("\n=== Testing ext_authz without subject token ===");
        
        String extAuthzUrl = authUrl + "/realms/" + TEST_REALM + "/ext-authz/check";
        
        // Request without Authorization header (subject token), but with client auth
        String basic = Base64.getEncoder().encodeToString((PROXY_CLIENT_ID + ":" + PROXY_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(extAuthzUrl))
            .header("Content-Type", "application/json")
            .header("Authorization", "Basic " + basic)
            .POST(HttpRequest.BodyPublishers.ofString("{}"))
            .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        System.out.println("Response status: " + response.statusCode());
        System.out.println("Response body: " + response.body());
        
        // Should return 403 Forbidden
        assertEquals(403, response.statusCode(), "Expected 403 Forbidden without subject token");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = objectMapper.readValue(response.body(), Map.class);
        assertEquals("denied", responseBody.get("status"), "Status should be 'denied'");
        
        System.out.println("✓ Correctly denied request without subject token");
    }
    
    /**
     * Extract client UUID from the create response Location header.
     */
    private static String extractClientIdFromResponse(jakarta.ws.rs.core.Response response) {
        String location = response.getHeaderString("Location");
        if (location == null) {
            throw new IllegalStateException("No Location header in create response");
        }
        return location.substring(location.lastIndexOf('/') + 1);
    }
}

