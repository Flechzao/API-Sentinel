package com.flechazo.apisentinel.standalone;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.execution.RequestExecutionEngine;
import burp.api.montoya.http.execution.RequestEngineOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Headless HTTP implementation backed by {@link java.net.http.HttpClient}.
 * Replaces Burp's {@code api.http().sendRequest()} in CLI mode.
 */
public class HeadlessHttp implements Http {

    private final HttpClient client;

    public HeadlessHttp() {
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(java.time.Duration.ofSeconds(30))
                .build();
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        HttpService service = request.httpService();
        String host = service.host();
        int port = service.port();
        boolean secure = service.secure();
        String scheme = secure ? "https" : "http";
        String url = request.url();
        if (url == null || url.isEmpty() || (!url.startsWith("http://") && !url.startsWith("https://"))) {
            String path = request.path();
            url = scheme + "://" + host + ":" + port + path;
        }

        String method = request.method();
        String body = request.bodyToString();

        Builder builder = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(java.time.Duration.ofSeconds(30));

        for (var header : request.headers()) {
            if (!header.name().equalsIgnoreCase("Content-Length")
                    && !header.name().equalsIgnoreCase("Host")) {
                builder.header(header.name(), header.value());
            }
        }

        if (body != null && !body.isEmpty()
                && ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method))) {
            builder.method(method, java.net.http.HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else {
            builder.method(method, java.net.http.HttpRequest.BodyPublishers.noBody());
        }

        try {
            java.net.http.HttpResponse<String> response = client.send(builder.build(), BodyHandlers.ofString(StandardCharsets.UTF_8));

            StringBuilder rawResp = new StringBuilder();
            rawResp.append("HTTP/1.1 ").append(response.statusCode()).append("\r\n");
            response.headers().map().forEach((k, v) -> {
                for (String val : v) rawResp.append(k).append(": ").append(val).append("\r\n");
            });
            rawResp.append("\r\n").append(response.body());

            HttpResponse resp = HttpResponse.httpResponse(rawResp.toString());
            return HeadlessHttpRequestResponse.of(request, resp);

        } catch (IOException | InterruptedException e) {
            String rawResp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n"
                    + "{\"error\": \"Connection failed: " + e.getMessage() + "\"}";
            HttpResponse resp = HttpResponse.httpResponse(rawResp);
            return HeadlessHttpRequestResponse.of(request, resp);
        }
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode mode) {
        return sendRequest(request);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode mode, String s) {
        return sendRequest(request);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions options) {
        return sendRequest(request);
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) {
        List<HttpRequestResponse> results = new ArrayList<>();
        for (HttpRequest req : requests) results.add(sendRequest(req));
        return results;
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode mode) {
        return sendRequests(requests);
    }

    @Override
    public Registration registerHttpHandler(HttpHandler handler) {
        return new NoopRegistration();
    }

    @Override
    public Registration registerSessionHandlingAction(SessionHandlingAction action) {
        return new NoopRegistration();
    }

    @Override
    public RequestExecutionEngine createRequestEngine() {
        return null;
    }

    @Override
    public RequestExecutionEngine createRequestEngine(RequestEngineOptions options) {
        return null;
    }

    @Override
    public ResponseKeywordsAnalyzer createResponseKeywordsAnalyzer(List<String> keywords) {
        return new EmptyResponseKeywordsAnalyzer();
    }

    @Override
    public ResponseVariationsAnalyzer createResponseVariationsAnalyzer() {
        return new EmptyResponseVariationsAnalyzer();
    }

    @Override
    public CookieJar cookieJar() {
        return new EmptyCookieJar();
    }

    // --- No-op implementations ---

    private static class NoopRegistration implements Registration {
        @Override public boolean isRegistered() { return false; }
        @Override public void deregister() {}
    }

    private static class EmptyResponseKeywordsAnalyzer implements ResponseKeywordsAnalyzer {
        @Override public java.util.Set<String> variantKeywords() { return java.util.Set.of(); }
        @Override public java.util.Set<String> invariantKeywords() { return java.util.Set.of(); }
        @Override public void updateWith(HttpResponse response) {}
    }

    private static class EmptyResponseVariationsAnalyzer implements ResponseVariationsAnalyzer {
        @Override public java.util.Set<burp.api.montoya.http.message.responses.analysis.AttributeType> variantAttributes() { return java.util.Set.of(); }
        @Override public java.util.Set<burp.api.montoya.http.message.responses.analysis.AttributeType> invariantAttributes() { return java.util.Set.of(); }
        @Override public void updateWith(HttpResponse response) {}
    }

    private static class EmptyCookieJar implements CookieJar {
        @Override public void setCookie(String url, String name, String value, String domain, java.time.ZonedDateTime expiration) {}
        @Override public List<burp.api.montoya.http.message.Cookie> cookies() { return List.of(); }
    }
}
