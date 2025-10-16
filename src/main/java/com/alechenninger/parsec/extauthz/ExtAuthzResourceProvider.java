package com.alechenninger.parsec.extauthz;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Provider for the ext_authz REST resource.
 * 
 * Keycloak will register this at: /realms/{realm}/ext-authz/*
 */
public class ExtAuthzResourceProvider implements RealmResourceProvider {
    
    private final KeycloakSession session;
    private final HttpHeaders headers;
    
    public ExtAuthzResourceProvider(KeycloakSession session, HttpHeaders headers) {
        this.session = session;
        this.headers = headers;
    }
    
    @Override
    public Object getResource() {
        return new ExtAuthzResource(session, headers);
    }
    
    @Override
    public void close() {
        // Nothing to close
    }
}

