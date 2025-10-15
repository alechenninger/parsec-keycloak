package com.alechenninger.parsec.extauthz;

import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.config.core.v3.HeaderValueOption;
import io.envoyproxy.envoy.service.auth.v3.AuthorizationGrpc;
import io.envoyproxy.envoy.service.auth.v3.CheckRequest;
import io.envoyproxy.envoy.service.auth.v3.CheckResponse;
import io.envoyproxy.envoy.service.auth.v3.OkHttpResponse;
import io.grpc.stub.StreamObserver;
import org.jboss.logging.Logger;

/**
 * Minimal POC implementation of Envoy's ext_authz gRPC service.
 * 
 * This service receives authorization requests from Envoy, validates incoming tokens,
 * performs token exchange, and injects the new token in response headers.
 * 
 * For POC: Simply returns OK with a dummy header to validate gRPC integration.
 */
public class ExtAuthzService extends AuthorizationGrpc.AuthorizationImplBase {
    
    private static final Logger logger = Logger.getLogger(ExtAuthzService.class);

    @Override
    public void check(CheckRequest request, StreamObserver<CheckResponse> responseObserver) {
        logger.infof("Received ext_authz check request from Envoy");
        
        try {
            // POC: Log the request details
            if (request.hasAttributes() && request.getAttributes().hasRequest()) {
                var httpRequest = request.getAttributes().getRequest().getHttp();
                logger.infof("HTTP Method: %s, Path: %s, Host: %s", 
                    httpRequest.getMethod(), 
                    httpRequest.getPath(),
                    httpRequest.getHost());
                
                // Log headers
                httpRequest.getHeadersMap().forEach((key, value) -> 
                    logger.debugf("Header: %s = %s", key, value));
            }
            
            // POC: Return OK with a dummy header to prove integration works
            CheckResponse response = CheckResponse.newBuilder()
                .setOkResponse(
                    OkHttpResponse.newBuilder()
                        .addHeaders(
                            HeaderValueOption.newBuilder()
                                .setHeader(
                                    HeaderValue.newBuilder()
                                        .setKey("x-parsec-status")
                                        .setValue("poc-success")
                                        .build()
                                )
                                .build()
                        )
                        .build()
                )
                .build();
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
            
            logger.infof("Successfully returned OK response");
            
        } catch (Exception e) {
            logger.errorf(e, "Error processing ext_authz request");
            
            // Return denied response on error
            CheckResponse errorResponse = CheckResponse.newBuilder()
                .setDeniedResponse(
                    io.envoyproxy.envoy.service.auth.v3.DeniedHttpResponse.newBuilder()
                        .setStatus(
                            io.envoyproxy.envoy.type.v3.HttpStatus.newBuilder()
                                .setCode(io.envoyproxy.envoy.type.v3.StatusCode.InternalServerError)
                                .build()
                        )
                        .setBody("Internal server error during authorization")
                        .build()
                )
                .build();
            
            responseObserver.onNext(errorResponse);
            responseObserver.onCompleted();
        }
    }
}

