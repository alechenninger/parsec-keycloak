package com.alechenninger.parsec.extauthz;

import org.keycloak.provider.Provider;

/**
 * Provider interface for managing the ext_authz gRPC server lifecycle.
 */
public interface ExtAuthzServerProvider extends Provider {
    
    /**
     * Starts the gRPC server if not already running.
     */
    void start();
    
    /**
     * Stops the gRPC server if running.
     */
    void stop();
    
    /**
     * @return true if the server is currently running
     */
    boolean isRunning();
    
    /**
     * @return the port the server is listening on, or -1 if not running
     */
    int getPort();
}

