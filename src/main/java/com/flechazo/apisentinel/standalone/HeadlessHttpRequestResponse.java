package com.flechazo.apisentinel.standalone;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;
import java.util.Optional;

/**
 * Simple {@link HttpRequestResponse} for CLI mode — stores request + response
 * directly, does NOT delegate to Montoya's static factory (which would
 * recurse through HeadlessObjectFactory → StackOverflow).
 */
public class HeadlessHttpRequestResponse implements HttpRequestResponse {

    private final HttpRequest request;
    private final HttpResponse response;

    private HeadlessHttpRequestResponse(HttpRequest request, HttpResponse response) {
        this.request = request;
        this.response = response;
    }

    public static HeadlessHttpRequestResponse of(HttpRequest request, HttpResponse response) {
        return new HeadlessHttpRequestResponse(request, response);
    }

    @Override public HttpRequest request() { return request; }
    @Override public HttpResponse response() { return response; }
    @Override public HttpService httpService() { return request != null ? request.httpService() : null; }
    @Override public Annotations annotations() { return null; }
    @Override public Optional<TimingData> timingData() { return Optional.empty(); }
    @Override public String url() { return request != null ? request.url() : ""; }
    @Override public boolean hasResponse() { return response != null; }
    @Override public ContentType contentType() { return ContentType.NONE; }
    @Override public short statusCode() { return response != null ? response.statusCode() : 0; }
    @Override public List<Marker> requestMarkers() { return List.of(); }
    @Override public List<Marker> responseMarkers() { return List.of(); }
    @Override public boolean contains(String s, boolean b) { return false; }
    @Override public boolean contains(java.util.regex.Pattern p) { return false; }
    @Override public HttpRequestResponse copyToTempFile() { return this; }
    @Override public HttpRequestResponse withAnnotations(Annotations a) { return this; }
    @Override public HttpRequestResponse withRequestMarkers(List<Marker> markers) { return this; }
    @Override public HttpRequestResponse withRequestMarkers(Marker... markers) { return this; }
    @Override public HttpRequestResponse withResponseMarkers(List<Marker> markers) { return this; }
    @Override public HttpRequestResponse withResponseMarkers(Marker... markers) { return this; }
}
