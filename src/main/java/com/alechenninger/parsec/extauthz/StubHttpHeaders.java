package com.alechenninger.parsec.extauthz;

import jakarta.ws.rs.core.*;

import java.util.*;

/**
 * Stub implementation of HttpHeaders for use in gRPC context where
 * there is no actual HTTP request.
 */
public class StubHttpHeaders implements HttpHeaders {
    
    private final Map<String, List<String>> headers;
    
    public StubHttpHeaders(Map<String, String> headerMap) {
        this.headers = new HashMap<>();
        if (headerMap != null) {
            headerMap.forEach((key, value) -> 
                this.headers.put(key, Collections.singletonList(value)));
        }
    }
    
    @Override
    public List<String> getRequestHeader(String name) {
        return headers.getOrDefault(name, Collections.emptyList());
    }
    
    @Override
    public String getHeaderString(String name) {
        List<String> values = getRequestHeader(name);
        return values.isEmpty() ? null : values.get(0);
    }
    
    @Override
    public MultivaluedMap<String, String> getRequestHeaders() {
        MultivaluedMap<String, String> result = new MultivaluedHashMap<>();
        headers.forEach(result::put);
        return result;
    }
    
    @Override
    public List<MediaType> getAcceptableMediaTypes() {
        return Collections.emptyList();
    }
    
    @Override
    public List<Locale> getAcceptableLanguages() {
        return Collections.emptyList();
    }
    
    @Override
    public MediaType getMediaType() {
        return null;
    }
    
    @Override
    public Locale getLanguage() {
        return null;
    }
    
    @Override
    public Map<String, Cookie> getCookies() {
        return Collections.emptyMap();
    }
    
    @Override
    public Date getDate() {
        return null;
    }
    
    @Override
    public int getLength() {
        return -1;
    }
}


