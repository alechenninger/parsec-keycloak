package com.alechenninger.parsec.testing;

import dasniko.testcontainers.keycloak.KeycloakContainer;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Test configuration that loads values from test.properties.
 * Maven resource filtering populates the properties from POM values.
 */
public class TestConfig {
    private static final Properties props = new Properties();
    
    static {
        try (InputStream in = TestConfig.class.getResourceAsStream("/test.properties")) {
            if (in != null) {
                props.load(in);
            } else {
                throw new RuntimeException("test.properties not found in classpath");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load test.properties", e);
        }
    }
    
    /**
     * Get the Keycloak version from the POM.
     */
    public static String getKeycloakVersion() {
        return props.getProperty("keycloak.version");
    }
    
    @SuppressWarnings("resource")
    public static KeycloakContainer createKeycloakContainer() {
        // Use classes directory + single dependencies JAR
        // This approach keeps our code always fresh while packaging all dependencies into one JAR
        // Using many dependency jars was excessively slow
        java.io.File dependenciesJar = new java.io.File("target/parsec-keycloak-1.0-SNAPSHOT-dependencies.jar");
        
        if (dependenciesJar.exists()) {
            return new ParsecKeycloakContainer(getKeycloakImage())
                    .withProviderClassesFrom("target/classes")
                    .withProviderLibsFrom(java.util.List.of(dependenciesJar));
        }
        
        // Fallback to just classes directory if dependencies JAR not yet built
        return new ParsecKeycloakContainer(getKeycloakImage())
                .withProviderClassesFrom("target/classes");
    }

    private static String getKeycloakImage() {
        return "quay.io/keycloak/keycloak:" + getKeycloakVersion();
    }
}
