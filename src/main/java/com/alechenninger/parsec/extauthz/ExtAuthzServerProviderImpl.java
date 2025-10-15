package com.alechenninger.parsec.extauthz;

import com.google.auto.service.AutoService;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Implementation of ExtAuthzServerProvider that manages the gRPC server lifecycle.
 * 
 * This provider starts a gRPC server on Keycloak initialization and handles
 * graceful shutdown when Keycloak stops.
 */
@AutoService(ExtAuthzServerProviderFactory.class)
public class ExtAuthzServerProviderImpl implements ExtAuthzServerProvider, ExtAuthzServerProviderFactory {
    
    private static final Logger logger = Logger.getLogger(ExtAuthzServerProviderImpl.class);
    private static final String PROVIDER_ID = "ext-authz-server";
    
    // Default configuration
    private static final int DEFAULT_PORT = 9191;
    private static final String DEFAULT_HOST = "0.0.0.0";
    
    // Singleton server instance shared across all sessions
    private static volatile Server grpcServer;
    private static volatile boolean serverStarted = false;
    private static int configuredPort = DEFAULT_PORT;
    
    private KeycloakSession session;
    
    public ExtAuthzServerProviderImpl() {
        // Default constructor for AutoService
    }
    
    private ExtAuthzServerProviderImpl(KeycloakSession session) {
        this.session = session;
    }
    
    @Override
    public ExtAuthzServerProvider create(KeycloakSession session) {
        return new ExtAuthzServerProviderImpl(session);
    }
    
    @Override
    public void init(Config.Scope config) {
        // Read configuration
        configuredPort = config.getInt("port", DEFAULT_PORT);
        String host = config.get("host", DEFAULT_HOST);
        
        // For POC: always auto-start the server
        boolean autoStart = true;
        
        logger.infof("Initializing ext_authz gRPC server provider - host: %s, port: %d, auto-start: %s", 
            host, configuredPort, autoStart);
        logger.infof("Config properties available: port=%s, host=%s", 
            config.get("port"), config.get("host"));
        
        if (autoStart) {
            startServer();
        }
    }
    
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.info("ext_authz gRPC server provider post-initialization complete");
    }
    
    @Override
    public void start() {
        startServer();
    }
    
    @Override
    public void stop() {
        stopServer();
    }
    
    @Override
    public boolean isRunning() {
        return serverStarted && grpcServer != null && !grpcServer.isShutdown();
    }
    
    @Override
    public int getPort() {
        return isRunning() ? configuredPort : -1;
    }
    
    /**
     * Static method to check if the server is running (for health checks).
     * @return true if the server is running
     */
    public static boolean isServerRunning() {
        return serverStarted && grpcServer != null && !grpcServer.isShutdown();
    }
    
    /**
     * Static method to get the server port (for health checks).
     * @return the server port, or -1 if not running
     */
    public static int getServerPort() {
        return isServerRunning() ? configuredPort : -1;
    }
    
    @Override
    public void close() {
        // Session-level close - don't stop the server
        // The server is managed at the factory level
    }
    
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    
    /**
     * Starts the gRPC server (thread-safe singleton initialization).
     */
    private static synchronized void startServer() {
        if (serverStarted) {
            logger.debug("ext_authz gRPC server already started");
            return;
        }
        
        try {
            logger.infof("Starting ext_authz gRPC server on port %d", configuredPort);
            
            grpcServer = ServerBuilder.forPort(configuredPort)
                .addService(new ExtAuthzService())
                .build()
                .start();
            
            serverStarted = true;
            
            logger.infof("ext_authz gRPC server started successfully on port %d", configuredPort);
            
            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Shutting down ext_authz gRPC server due to JVM shutdown");
                stopServer();
            }));
            
        } catch (IOException e) {
            logger.errorf(e, "Failed to start ext_authz gRPC server on port %d", configuredPort);
            throw new RuntimeException("Failed to start ext_authz gRPC server", e);
        }
    }
    
    /**
     * Stops the gRPC server gracefully.
     */
    private static synchronized void stopServer() {
        if (!serverStarted || grpcServer == null) {
            logger.debug("ext_authz gRPC server not running");
            return;
        }
        
        try {
            logger.info("Stopping ext_authz gRPC server");
            
            grpcServer.shutdown();
            
            // Wait for graceful shutdown
            if (!grpcServer.awaitTermination(10, TimeUnit.SECONDS)) {
                logger.warn("ext_authz gRPC server did not terminate gracefully, forcing shutdown");
                grpcServer.shutdownNow();
                
                if (!grpcServer.awaitTermination(5, TimeUnit.SECONDS)) {
                    logger.error("ext_authz gRPC server did not terminate");
                }
            }
            
            serverStarted = false;
            grpcServer = null;
            
            logger.info("ext_authz gRPC server stopped successfully");
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error("Interrupted while stopping ext_authz gRPC server", e);
            grpcServer.shutdownNow();
        }
    }
}

