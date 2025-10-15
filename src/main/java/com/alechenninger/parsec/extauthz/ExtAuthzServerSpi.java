package com.alechenninger.parsec.extauthz;

import com.google.auto.service.AutoService;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * SPI definition for the ext_authz gRPC server.
 * This registers the SPI with Keycloak's provider framework.
 */
@AutoService(Spi.class)
public class ExtAuthzServerSpi implements Spi {
    
    @Override
    public boolean isInternal() {
        return false;
    }
    
    @Override
    public String getName() {
        return "ext-authz-server";
    }
    
    @Override
    public Class<? extends Provider> getProviderClass() {
        return ExtAuthzServerProvider.class;
    }
    
    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return ExtAuthzServerProviderFactory.class;
    }
}

