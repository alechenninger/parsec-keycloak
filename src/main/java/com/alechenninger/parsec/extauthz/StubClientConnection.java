package com.alechenninger.parsec.extauthz;

import org.keycloak.common.ClientConnection;

/**
 * Stub implementation of ClientConnection for use in gRPC context where
 * there is no actual HTTP connection.
 */
public class StubClientConnection implements ClientConnection {
    
    private final String remoteAddr;
    private final int remotePort;
    
    public StubClientConnection(String remoteAddr, int remotePort) {
        this.remoteAddr = remoteAddr;
        this.remotePort = remotePort;
    }
    
    @Override
    public String getRemoteAddr() {
        return remoteAddr;
    }
    
    @Override
    public String getRemoteHost() {
        return remoteAddr;
    }
    
    @Override
    public int getRemotePort() {
        return remotePort;
    }
    
    @Override
    public String getLocalAddr() {
        return "127.0.0.1";
    }
    
    @Override
    public int getLocalPort() {
        return 9191; // gRPC port
    }
}


