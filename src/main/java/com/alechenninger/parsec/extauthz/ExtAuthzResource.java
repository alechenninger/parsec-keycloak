package com.alechenninger.parsec.extauthz;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.cors.Cors;

import java.util.HashMap;
import java.util.Map;

/**
 * JAX-RS resource implementing Envoy's HTTP ext_authz protocol.
 * 
 * Envoy HTTP ext_authz sends requests to: POST /check
 * With headers forwarded in the request body or as HTTP headers.
 * 
 * This implementation:
 * 1. Authenticates the calling client (proxy) via bearer token in X-Proxy-Authorization
 * 2. Extracts the subject token from Authorization header
 * 3. Performs OAuth 2.0 Token Exchange (RFC 8693) using Keycloak's native capabilities
 * 4. Returns appropriate headers for Envoy to inject into the upstream request
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ExtAuthzResource {
    
    private static final Logger logger = Logger.getLogger(ExtAuthzResource.class);
    private static final String CLIENT_AUTH_HEADER = "x-proxy-authorization";
    
    private final KeycloakSession session;
    private final HttpHeaders headers;
    
    public ExtAuthzResource(KeycloakSession session, HttpHeaders headers) {
        this.session = session;
        this.headers = headers;
    }
    
    /**
     * Envoy ext_authz check endpoint (HTTP protocol).
     * 
     * Envoy sends: POST /check
     * With request headers either in body or as HTTP headers.
     * 
     * Response format:
     * - 200 OK: Allow request, optionally with additional headers
     * - 403 Forbidden: Deny request
     * - Other codes: Envoy treats as errors
     */
    @POST
    @Path("/check")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response check(
            @Context HttpHeaders httpHeaders,
            String bodyJson) {
        
        System.out.println("=== EXT_AUTHZ CHECK CALLED ===");
        logger.infof("Received ext_authz check request from Envoy");
        
        // Parse JSON body
        Map<String, Object> body = null;
        if (bodyJson != null && !bodyJson.isEmpty()) {
            try {
                body = org.keycloak.util.JsonSerialization.readValue(bodyJson, Map.class);
            } catch (Exception e) {
                logger.errorf(e, "Failed to parse request body JSON");
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("status", "denied", "reason", "Invalid JSON body"))
                    .build();
            }
        }
        
        try {
            System.out.println("=== ENTERING TRY BLOCK ===");
            // Step 1: Authenticate the calling client (proxy/gateway)
            String clientAuthHeader = httpHeaders.getHeaderString(CLIENT_AUTH_HEADER);
            if (clientAuthHeader == null || !clientAuthHeader.toLowerCase().startsWith("bearer ")) {
                logger.warn("Missing or invalid " + CLIENT_AUTH_HEADER + " header");
                return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("status", "denied", "reason", "Client authentication required"))
                    .build();
            }
            
            String clientTokenString = clientAuthHeader.substring("Bearer ".length());
            ClientModel authenticatedClient = verifyClientToken(clientTokenString);
            logger.infof("Authenticated client: %s", authenticatedClient.getClientId());
            
            // Step 2: Extract subject token from the request body
            // Envoy sends the original client request headers in the body
            // Body format: { "attributes": { "request": { "http": { "headers": { "authorization": "Bearer ..." } } } } }
            String subjectToken = extractSubjectTokenFromBody(body);
            if (subjectToken == null) {
                logger.warn("No authorization header found in proxied request");
                return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("status", "denied", "reason", "No authorization in proxied request"))
                    .build();
            }
            
            // Step 3: Perform token exchange
            AccessTokenResponse exchangeResult;
            try {
                exchangeResult = performTokenExchange(
                    authenticatedClient,
                    subjectToken,
                    httpHeaders
                );
                logger.infof("Token exchange successful");
            } catch (Exception e) {
                logger.errorf(e, "Token exchange failed with exception");
                return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("status", "denied", "reason", "Token exchange failed: " + e.getMessage()))
                    .build();
            }
            
            // Step 4: Return OK response with new token as header
            // Envoy ext_authz HTTP protocol expects specific response format
            Map<String, Object> response = new HashMap<>();
            response.put("status", "ok");
            
            // Headers to inject into the upstream request
            Map<String, String> headersToAdd = new HashMap<>();
            headersToAdd.put("authorization", exchangeResult.getTokenType() + " " + exchangeResult.getToken());
            headersToAdd.put("x-parsec-token-exchanged", "true");
            response.put("headers", headersToAdd);
            
            // Headers to remove from the upstream request
            response.put("headers_to_remove", new String[]{"authorization"}); // Remove original, we're adding the new one
            
            return Response.ok(response).build();
            
        } catch (VerificationException e) {
            logger.errorf(e, "Token verification failed");
            return Response.status(Response.Status.FORBIDDEN)
                .entity(Map.of("status", "denied", "reason", "Token verification failed: " + e.getMessage()))
                .build();
                
        } catch (Exception e) {
            logger.errorf(e, "Token exchange failed");
            return Response.status(Response.Status.FORBIDDEN)
                .entity(Map.of("status", "denied", "reason", "Token exchange failed: " + e.getMessage()))
                .build();
        }
    }
    
    /**
     * Verify the client authentication token and return the authenticated client.
     */
    private ClientModel verifyClientToken(String tokenString) throws VerificationException {
        // Parse token to extract realm from issuer
        TokenVerifier<AccessToken> preliminaryVerifier = TokenVerifier.create(tokenString, AccessToken.class);
        AccessToken preliminaryToken;
        try {
            preliminaryToken = preliminaryVerifier.parse().getToken();
        } catch (VerificationException e) {
            throw new VerificationException("Failed to parse token: " + e.getMessage(), e);
        }
        
        // Extract realm name from issuer
        String issuer = preliminaryToken.getIssuer();
        if (issuer == null) {
            throw new VerificationException("Token missing issuer claim");
        }
        
        String realmName = extractRealmFromIssuer(issuer);
        logger.debugf("Extracted realm from token: %s", realmName);
        
        // Look up the realm
        RealmModel realm = session.realms().getRealmByName(realmName);
        if (realm == null) {
            throw new VerificationException("Realm not found: " + realmName);
        }
        
        // Set the realm in the session context
        session.getContext().setRealm(realm);
        
        // Perform full token verification with signature check
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class);
        
        String kid = verifier.getHeader().getKeyId();
        if (kid == null) {
            throw new VerificationException("Token header missing key ID (kid)");
        }
        
        SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class,
            verifier.getHeader().getAlgorithm().name()).verifier(kid);
        
        AccessToken token = verifier
            .checkActive(true)
            .checkTokenType(true)
            .withChecks(TokenVerifier.SUBJECT_EXISTS_CHECK)
            .verifierContext(verifierContext)
            .verify()
            .getToken();
        
        // Extract client ID from the token
        String clientId = token.getIssuedFor();
        if (clientId == null && token.getAudience() != null && token.getAudience().length == 1) {
            clientId = token.getAudience()[0];
        }
        
        if (clientId == null) {
            throw new VerificationException("Client ID not found in token (azp or aud)");
        }
        
        // Verify client exists and is enabled
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || !client.isEnabled()) {
            throw new VerificationException("Client not found or not enabled: " + clientId);
        }
        
        return client;
    }
    
    /**
     * Perform token exchange using Keycloak's TokenExchangeProvider SPI.
     * 
     * Since we're already in a JAX-RS request context, we can use the real HTTP context
     * from the current request rather than making another HTTP call.
     * 
     * See https://www.keycloak.org/securing-apps/token-exchange for details on standard token exchange.
     */
    private AccessTokenResponse performTokenExchange(
            ClientModel client,
            String subjectToken,
            HttpHeaders httpHeaders) throws Exception {
        
        RealmModel realm = session.getContext().getRealm();
        
        logger.infof("Performing token exchange for client: %s", client.getClientId());
        
        // Build form parameters for token exchange (RFC 8693)
        // Per https://www.keycloak.org/securing-apps/token-exchange
        MultivaluedHashMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE);
        formParams.putSingle(OAuth2Constants.CLIENT_ID, client.getClientId());
        formParams.putSingle(OAuth2Constants.CLIENT_SECRET, client.getSecret());  // Client authentication
        formParams.putSingle(OAuth2Constants.SUBJECT_TOKEN, subjectToken);
        formParams.putSingle(OAuth2Constants.SUBJECT_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
        formParams.putSingle(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
        // Specify audience as the same client for POC (avoids permission issues)
        // TODO: Make this configurable and set up proper cross-client exchange permissions
        formParams.putSingle(OAuth2Constants.AUDIENCE, client.getClientId());
        
        // Create event builder for auditing
        EventBuilder eventBuilder = new EventBuilder(realm, session);
        eventBuilder.event(org.keycloak.events.EventType.TOKEN_EXCHANGE);
        
        // Create TokenManager - required by TokenExchangeProviders
        TokenManager tokenManager = new TokenManager();
        
        // Use the REAL HTTP context from the current request
        // We're already in a JAX-RS resource, so we have actual HttpHeaders and ClientConnection
        org.keycloak.common.ClientConnection clientConnection = session.getContext().getConnection();
        var cors = Cors.builder().auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        
        // Create token exchange context with the real HTTP context
        // Note: Pass null for CORS - we'll handle CORS ourselves if needed
        TokenExchangeContext context = new TokenExchangeContext(
            session,
            formParams,
            cors,  // CORS handler - pass null, we'll handle response ourselves
            realm,
            eventBuilder,
            client,
            clientConnection,  // Use real connection from current request
            httpHeaders,       // Use real HTTP headers from current request (@Context injected)
            tokenManager,
            Map.of()  // requestParameters (clientAuthAttributes) - not needed for our use case
        );
        
        // Find the first TokenExchangeProvider that supports this exchange
        TokenExchangeProvider tokenExchangeProvider = session.getKeycloakSessionFactory()
            .getProviderFactoriesStream(TokenExchangeProvider.class)
            .sorted((f1, f2) -> f2.order() - f1.order())  // Higher order = higher priority
            .map(f -> session.getProvider(TokenExchangeProvider.class, f.getId()))
            .filter(p -> p.supports(context))
            .findFirst()
            .orElseThrow(() -> {
                String reason = context.getUnsupportedReason();
                if (reason != null) {
                    logger.errorf("Token exchange not supported: %s", reason);
                    return new IllegalStateException("Token exchange not supported: " + reason);
                } else {
                    logger.error("No token exchange provider available");
                    return new IllegalStateException("No token exchange provider available");
                }
            });
        
        logger.infof("Using TokenExchangeProvider: %s", tokenExchangeProvider.getClass().getSimpleName());
        
        // Perform the token exchange
        // Note: exchange() may try to add CORS headers - we'll catch that and handle it
        jakarta.ws.rs.core.Response response;
        try {
            response = tokenExchangeProvider.exchange(context);
        } catch (NullPointerException e) {
            // This might be the CORS NPE - log it and rethrow with more context
            logger.errorf(e, "NPE during token exchange (likely CORS-related)");
            throw new IllegalStateException("Token exchange failed due to CORS handling: " + e.getMessage(), e);
        }
        
        if (response == null) {
            throw new IllegalStateException("Token exchange returned null response");
        }
        
        if (response.getStatus() != 200) {
            String errorMsg = "Token exchange failed with status: " + response.getStatus();
            Object entity = response.getEntity();
            if (entity != null) {
                errorMsg += ", entity: " + entity;
                logger.errorf("Token exchange error: %s", entity);
            }
            throw new IllegalStateException(errorMsg);
        }
        
        Object entity = response.getEntity();
        if (!(entity instanceof AccessTokenResponse)) {
            throw new IllegalStateException("Unexpected response entity type: " + 
                (entity != null ? entity.getClass().getName() : "null"));
        }
        
        logger.infof("Token exchange successful");
        return (AccessTokenResponse) entity;
    }
    
    /**
     * Extract subject token from Envoy ext_authz request body.
     * 
     * Envoy sends the original client request headers in the body:
     * { "attributes": { "request": { "http": { "headers": { "authorization": "Bearer ..." } } } } }
     */
    @SuppressWarnings("unchecked")
    private String extractSubjectTokenFromBody(Map<String, Object> body) {
        if (body == null) {
            logger.warn("Request body is null");
            return null;
        }
        
        try {
            // Navigate through the nested structure
            Map<String, Object> attributes = (Map<String, Object>) body.get("attributes");
            if (attributes == null) {
                logger.warn("No 'attributes' in request body");
                return null;
            }
            
            Map<String, Object> request = (Map<String, Object>) attributes.get("request");
            if (request == null) {
                logger.warn("No 'request' in attributes");
                return null;
            }
            
            Map<String, Object> http = (Map<String, Object>) request.get("http");
            if (http == null) {
                logger.warn("No 'http' in request");
                return null;
            }
            
            Map<String, Object> headers = (Map<String, Object>) http.get("headers");
            if (headers == null) {
                logger.warn("No 'headers' in http");
                return null;
            }
            
            // Get authorization header (Envoy lowercases header names)
            String authHeader = (String) headers.get("authorization");
            if (authHeader == null) {
                logger.warn("No 'authorization' header in proxied request");
                return null;
            }
            
            // Extract token from "Bearer <token>"
            if (authHeader.toLowerCase().startsWith("bearer ")) {
                return authHeader.substring("Bearer ".length());
            }
            
            // Return as-is if not Bearer format
            return authHeader;
            
        } catch (ClassCastException e) {
            logger.errorf(e, "Failed to parse request body structure");
            return null;
        }
    }
    
    /**
     * Extract realm name from issuer URL.
     */
    private String extractRealmFromIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            throw new IllegalArgumentException("Issuer is null or empty");
        }
        
        int realmsIndex = issuer.indexOf("/realms/");
        if (realmsIndex == -1) {
            throw new IllegalArgumentException("Invalid issuer format, missing '/realms/': " + issuer);
        }
        
        String realmName = issuer.substring(realmsIndex + "/realms/".length());
        
        int slashIndex = realmName.indexOf('/');
        if (slashIndex != -1) {
            realmName = realmName.substring(0, slashIndex);
        }
        
        return realmName;
    }
}

