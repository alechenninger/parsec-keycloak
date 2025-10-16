package com.alechenninger.parsec.extauthz;

import com.google.auto.service.AutoService;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for creating ExtAuthz REST resource providers.
 * 
 * This registers the ext_authz endpoint at: /realms/{realm}/ext-authz/*
 */
@AutoService(RealmResourceProviderFactory.class)
public class ExtAuthzResourceProviderFactory implements RealmResourceProviderFactory {
    
    public static final String ID = "ext-authz";
    
    @Context
    private HttpHeaders headers;
    
    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new ExtAuthzResourceProvider(session, headers);
    }
    
    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }
    
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }
    
    @Override
    public void close() {
        // Nothing to close
    }
    
    @Override
    public String getId() {
        return ID;
    }
}

