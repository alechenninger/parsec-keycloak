package com.alechenninger.parsec.extauthz;

import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.service.auth.v3.AttributeContext;
import io.envoyproxy.envoy.service.auth.v3.CheckRequest;
import io.envoyproxy.envoy.service.auth.v3.CheckResponse;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for ExtAuthzService POC implementation.
 */
class ExtAuthzServiceTest {
    
    private ExtAuthzService service;
    private TestStreamObserver responseObserver;
    
    @BeforeEach
    void setUp() {
        service = new ExtAuthzService();
        responseObserver = new TestStreamObserver();
    }
    
    @Test
    void testCheckReturnsOkResponse() {
        // Given: A minimal check request
        CheckRequest request = CheckRequest.newBuilder()
            .setAttributes(
                AttributeContext.newBuilder()
                    .setRequest(
                        AttributeContext.Request.newBuilder()
                            .setHttp(
                                AttributeContext.HttpRequest.newBuilder()
                                    .setMethod("GET")
                                    .setPath("/api/test")
                                    .setHost("example.com")
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build();
        
        // When: check is called
        service.check(request, responseObserver);
        
        // Then: Response should be OK with our POC header
        assertThat(responseObserver.completed).isTrue();
        assertThat(responseObserver.responses).hasSize(1);
        
        CheckResponse response = responseObserver.responses.get(0);
        assertThat(response.hasOkResponse()).isTrue();
        
        // Verify POC header is present
        boolean foundHeader = false;
        for (var headerOption : response.getOkResponse().getHeadersList()) {
            HeaderValue header = headerOption.getHeader();
            if ("x-parsec-status".equals(header.getKey()) && 
                "poc-success".equals(header.getValue())) {
                foundHeader = true;
                break;
            }
        }
        
        assertThat(foundHeader).isTrue()
            .withFailMessage("Expected to find x-parsec-status header with value poc-success");
    }
    
    @Test
    void testCheckWithHeadersLogsRequest() {
        // Given: A check request with headers
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer test-token");
        headers.put("x-custom-header", "custom-value");
        
        CheckRequest request = CheckRequest.newBuilder()
            .setAttributes(
                AttributeContext.newBuilder()
                    .setRequest(
                        AttributeContext.Request.newBuilder()
                            .setHttp(
                                AttributeContext.HttpRequest.newBuilder()
                                    .setMethod("POST")
                                    .setPath("/api/protected")
                                    .setHost("api.example.com")
                                    .putAllHeaders(headers)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build();
        
        // When: check is called
        service.check(request, responseObserver);
        
        // Then: Should complete successfully
        assertThat(responseObserver.completed).isTrue();
        assertThat(responseObserver.responses).hasSize(1);
        assertThat(responseObserver.responses.get(0).hasOkResponse()).isTrue();
    }
    
    /**
     * Test implementation of StreamObserver for capturing responses.
     */
    static class TestStreamObserver implements StreamObserver<CheckResponse> {
        List<CheckResponse> responses = new ArrayList<>();
        boolean completed = false;
        Throwable error = null;
        
        @Override
        public void onNext(CheckResponse value) {
            responses.add(value);
        }
        
        @Override
        public void onError(Throwable t) {
            error = t;
        }
        
        @Override
        public void onCompleted() {
            completed = true;
        }
    }
}

