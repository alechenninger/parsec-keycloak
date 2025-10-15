package com.alechenninger.parsec.extauthz;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;

/**
 * Factory for creating ExtAuthzServerProvider instances.
 */
public interface ExtAuthzServerProviderFactory extends ProviderFactory<ExtAuthzServerProvider> {
    
    @Override
    default void init(Config.Scope config) {
        // Configuration initialization if needed
    }
    
    @Override
    default void postInit(KeycloakSessionFactory factory) {
        // Post-initialization if needed
    }
    
    @Override
    default void close() {
        // Cleanup on shutdown
    }
}

