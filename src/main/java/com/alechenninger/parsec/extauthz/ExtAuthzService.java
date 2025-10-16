package com.alechenninger.parsec.extauthz;

import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.config.core.v3.HeaderValueOption;
import io.envoyproxy.envoy.service.auth.v3.CheckRequest;
import io.envoyproxy.envoy.service.auth.v3.CheckResponse;
import io.envoyproxy.envoy.service.auth.v3.OkHttpResponse;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;

import java.util.Optional;

/**
 * gRPC service implementing Envoy's ext_authz protocol with CDI integration.
 * 
 * This service performs token exchange using Keycloak's TokenExchangeProvider SPI (RFC 8693):
 * 1. Authenticates the calling client (proxy/gateway) via bearer token in X-Proxy-Authorization header
 * 2. Extracts the subject token from the Authorization header
 * 3. Performs token exchange using TokenExchangeProvider
 * 4. Injects the exchanged token into response headers
 * 
 * Hybrid approach:
 * - Uses CDI (@ApplicationScoped, @Inject) for dependency injection from Keycloak's Quarkus runtime
 * - Manually registered with gRPC server (not @GrpcService) since Keycloak extensions  
 *   are loaded at runtime, after Quarkus build-time processing
 * - Leverages Keycloak's existing Quarkus infrastructure without requiring build-time gRPC setup
 */
@ApplicationScoped
public class ExtAuthzService extends io.envoyproxy.envoy.service.auth.v3.AuthorizationGrpc.AuthorizationImplBase {
    
    private static final Logger logger = Logger.getLogger(ExtAuthzService.class);
    private static final String CLIENT_AUTH_HEADER = "x-proxy-authorization";
    
    @Inject
    KeycloakSessionFactory sessionFactory;

    /**
     * Main entry point for ext_authz check requests.
     * 
     * Called by the gRPC server on the gRPC worker thread pool.
     * Uses Keycloak session management for database transactions.
     */
    @Override
    public void check(CheckRequest request, io.grpc.stub.StreamObserver<CheckResponse> responseObserver) {
        logger.infof("Received ext_authz check request from Envoy");
        
        // Create a Keycloak session for this request
        try (KeycloakSession session = sessionFactory.create()) {
            try {
                session.getTransactionManager().begin();
                
                CheckResponse response = processCheck(request, session);
                
                session.getTransactionManager().commit();
                
                responseObserver.onNext(response);
                responseObserver.onCompleted();
                
            } catch (Exception e) {
                session.getTransactionManager().rollback();
                logger.errorf(e, "Error processing ext_authz request");
                CheckResponse errorResponse = createDeniedResponse(
                    io.envoyproxy.envoy.type.v3.StatusCode.InternalServerError,
                    "Internal server error during authorization"
                );
                responseObserver.onNext(errorResponse);
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            logger.errorf(e, "Failed to create Keycloak session");
            CheckResponse errorResponse = createDeniedResponse(
                io.envoyproxy.envoy.type.v3.StatusCode.InternalServerError,
                "Failed to create session"
            );
            responseObserver.onNext(errorResponse);
            responseObserver.onCompleted();
        }
    }
    
    private CheckResponse processCheck(CheckRequest request, KeycloakSession session) {
        // Extract HTTP request details
        if (!request.hasAttributes() || !request.getAttributes().hasRequest()) {
            throw new IllegalArgumentException("Request must have attributes with HTTP request");
        }
        
        var httpRequest = request.getAttributes().getRequest().getHttp();
        logger.infof("HTTP Method: %s, Path: %s, Host: %s",
            httpRequest.getMethod(),
            httpRequest.getPath(),
            httpRequest.getHost());
        
        // Step 1: Authenticate the calling client (proxy/gateway) via bearer token
        String clientAuthHeader = httpRequest.getHeadersMap().get(CLIENT_AUTH_HEADER);
        if (clientAuthHeader == null || !clientAuthHeader.toLowerCase().startsWith("bearer ")) {
            logger.warn("Missing or invalid " + CLIENT_AUTH_HEADER + " header");
            return createDeniedResponse(io.envoyproxy.envoy.type.v3.StatusCode.Unauthorized,
                "Client authentication required via " + CLIENT_AUTH_HEADER + " header");
        }
        
        String clientTokenString = clientAuthHeader.substring("Bearer ".length());
        
        // Verify client token and get the authenticated client
        ClientModel authenticatedClient;
        try {
            authenticatedClient = verifyClientToken(clientTokenString, session);
            logger.infof("Authenticated client: %s", authenticatedClient.getClientId());
        } catch (Exception e) {
            logger.errorf(e, "Client authentication failed");
            return createDeniedResponse(io.envoyproxy.envoy.type.v3.StatusCode.Unauthorized,
                "Client authentication failed: " + e.getMessage());
        }
        
        // Step 2: Extract Authorization header (subject token)
        Optional<String> subjectToken = extractAuthorizationToken(httpRequest);
        
        if (subjectToken.isEmpty()) {
            logger.warn("No Authorization header found in request");
            return createDeniedResponse(io.envoyproxy.envoy.type.v3.StatusCode.Unauthorized,
                "Authorization header required");
        }
        
        // Step 3: Perform token exchange using TokenExchangeProvider
        try {
            AccessTokenResponse exchangeResult = performTokenExchange(
                session,
                authenticatedClient,
                subjectToken.get()
            );
            
            logger.debugf("Token exchange successful");
            
            // Build OK response with exchanged token
            var okResponseBuilder = OkHttpResponse.newBuilder()
                // Remove the original Authorization header
                .addHeadersToRemove("authorization")
                // Add the new token as Authorization header
                .addHeaders(HeaderValueOption.newBuilder()
                    .setHeader(HeaderValue.newBuilder()
                        .setKey("authorization")
                        .setValue(exchangeResult.getTokenType() + " " + exchangeResult.getToken())
                        .build())
                    .build())
                // Add status header for debugging
                .addHeaders(HeaderValueOption.newBuilder()
                    .setHeader(HeaderValue.newBuilder()
                        .setKey("x-parsec-token-exchanged")
                        .setValue("true")
                        .build())
                    .build());
            
            CheckResponse response = CheckResponse.newBuilder()
                .setOkResponse(okResponseBuilder.build())
                .build();
            
            logger.infof("Successfully returning OK response with exchanged token");
            return response;
            
        } catch (Exception e) {
            logger.errorf(e, "Token exchange failed");
            return createDeniedResponse(io.envoyproxy.envoy.type.v3.StatusCode.Unauthorized,
                "Token exchange failed: " + e.getMessage());
        }
    }
    
    /**
     * Verify the client authentication token and return the authenticated client.
     */
    private ClientModel verifyClientToken(String tokenString, KeycloakSession session) 
            throws VerificationException {
        // First, parse the token to extract the realm (issuer)
        // We do this without signature verification first to get the realm name
        TokenVerifier<AccessToken> preliminaryVerifier = TokenVerifier.create(tokenString, AccessToken.class);
        AccessToken preliminaryToken;
        try {
            preliminaryToken = preliminaryVerifier.parse().getToken();
        } catch (VerificationException e) {
            throw new VerificationException("Failed to parse token: " + e.getMessage(), e);
        }
        
        // Extract realm name from issuer (format: http://localhost:8080/realms/test-realm)
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
        
        // Set the realm in the session context so it's available for subsequent operations
        session.getContext().setRealm(realm);
        
        // Now perform full token verification with signature check
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
        
        // Extract client ID from the token (azp = authorized party or aud)
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
     * This follows Keycloak's own pattern from TokenExchangeGrantType.java:
     * 1. Get all TokenExchangeProvider factories
     * 2. Sort by order (higher order = higher priority)
     * 3. Find the first provider that supports this exchange
     * 4. Execute the exchange
     * 
     * With Quarkus gRPC and @Blocking, we now have a proper request context,
     * which should allow TokenExchangeProvider to access RequestScoped beans.
     */
    private AccessTokenResponse performTokenExchange(
            KeycloakSession session,
            ClientModel client,
            String subjectToken) throws Exception {
        
        RealmModel realm = session.getContext().getRealm();
        
        // Build form parameters for token exchange (RFC 8693 format)
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE);
        formParams.putSingle(OAuth2Constants.SUBJECT_TOKEN, subjectToken);
        formParams.putSingle(OAuth2Constants.SUBJECT_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
        
        // Create event builder for auditing
        EventBuilder eventBuilder = new EventBuilder(realm, session);
        
        // Create TokenManager - required by TokenExchangeProviders
        TokenManager tokenManager = new TokenManager();
        
        // Create stub HTTP context objects for gRPC environment
        // Even with Quarkus gRPC, TokenExchangeProvider still expects HTTP context objects
        StubClientConnection clientConnection = new StubClientConnection("gRPC", 0);
        StubHttpHeaders httpHeaders = new StubHttpHeaders(null);
        
        // Create token exchange context with all required parameters
        TokenExchangeContext context = new TokenExchangeContext(
            session,
            formParams,
            null, // cors - not needed for internal exchange
            realm,
            eventBuilder,
            client,
            clientConnection,  // Stub connection for gRPC context
            httpHeaders,       // Stub headers for gRPC context
            tokenManager, // customData - TokenManager is used by providers
            null  // requestParameters (clientAuthAttributes in Keycloak's impl)
        );

        // Find the first TokenExchangeProvider that supports this exchange
        // Following Keycloak's pattern: sort by order descending, filter by supports()
        TokenExchangeProvider tokenExchangeProvider = session.getKeycloakSessionFactory()
            .getProviderFactoriesStream(TokenExchangeProvider.class)
            .sorted((f1, f2) -> f2.order() - f1.order())  // Higher order = higher priority
            .map(f -> session.getProvider(TokenExchangeProvider.class, f.getId()))
            .filter(p -> p.supports(context))
            .findFirst()
            .orElseThrow(() -> {
                // Provide detailed error message if no provider supports this exchange
                String reason = context.getUnsupportedReason();
                if (reason != null) {
                    logger.errorf("Token exchange not supported: %s", reason);
                    return new IllegalStateException("Token exchange not supported: " + reason);
                } else {
                    logger.error("No token exchange provider available");
                    return new IllegalStateException("No token exchange provider available");
                }
            });

        logger.debugf("Using TokenExchangeProvider: %s", tokenExchangeProvider.getClass().getName());

        // Perform the token exchange
        jakarta.ws.rs.core.Response response = tokenExchangeProvider.exchange(context);
        
        if (response == null) {
            throw new IllegalStateException("Token exchange returned null response");
        }
        
        // Extract the AccessTokenResponse from the Response entity
        if (response.getStatus() != 200) {
            String errorMsg = "Token exchange failed with status: " + response.getStatus();
            Object entity = response.getEntity();
            if (entity != null) {
                errorMsg += ", entity: " + entity;
            }
            throw new IllegalStateException(errorMsg);
        }
        
        Object entity = response.getEntity();
        if (!(entity instanceof AccessTokenResponse)) {
            throw new IllegalStateException("Unexpected response entity type: " + 
                (entity != null ? entity.getClass().getName() : "null"));
        }

        return (AccessTokenResponse) entity;
    }
    
    /**
     * Extract the bearer token from the Authorization header.
     */
    private Optional<String> extractAuthorizationToken(
            io.envoyproxy.envoy.service.auth.v3.AttributeContext.HttpRequest httpRequest) {
        String authHeader = httpRequest.getHeadersMap().get("authorization");
        if (authHeader == null || authHeader.isEmpty()) {
            return Optional.empty();
        }
        
        // Remove "Bearer " prefix if present
        if (authHeader.toLowerCase().startsWith("bearer ")) {
            return Optional.of(authHeader.substring(7));
        }
        
        return Optional.of(authHeader);
    }
    
    /**
     * Extract realm name from issuer URL.
     * Issuer format: http://localhost:8080/realms/test-realm
     * Returns: test-realm
     */
    private String extractRealmFromIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            throw new IllegalArgumentException("Issuer is null or empty");
        }
        
        // Find "/realms/" in the issuer URL
        int realmsIndex = issuer.indexOf("/realms/");
        if (realmsIndex == -1) {
            throw new IllegalArgumentException("Invalid issuer format, missing '/realms/': " + issuer);
        }
        
        // Extract everything after "/realms/"
        String realmName = issuer.substring(realmsIndex + "/realms/".length());
        
        // Remove any trailing slashes or paths
        int slashIndex = realmName.indexOf('/');
        if (slashIndex != -1) {
            realmName = realmName.substring(0, slashIndex);
        }
        
        return realmName;
    }
    
    /**
     * Create a denied response with the given status and message.
     */
    private CheckResponse createDeniedResponse(io.envoyproxy.envoy.type.v3.StatusCode statusCode,
                                               String message) {
        return CheckResponse.newBuilder()
            .setDeniedResponse(
                io.envoyproxy.envoy.service.auth.v3.DeniedHttpResponse.newBuilder()
                    .setStatus(
                        io.envoyproxy.envoy.type.v3.HttpStatus.newBuilder()
                            .setCode(statusCode)
                            .build()
                    )
                    .setBody(message)
                    .build()
            )
            .build();
    }
}
