package com.flechazo.apisentinel.standalone;

import burp.api.montoya.core.Registration;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import burp.api.montoya.proxy.ProxyWebSocketHistoryFilter;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;

import java.util.List;

/**
 * Headless {@link Proxy} — returns empty history (no proxy in CLI mode).
 */
public class HeadlessProxy implements Proxy {

    @Override public void enableIntercept() {}
    @Override public void disableIntercept() {}
    @Override public boolean isInterceptEnabled() { return false; }

    @Override public List<ProxyHttpRequestResponse> history() { return List.of(); }
    @Override public List<ProxyHttpRequestResponse> history(ProxyHistoryFilter filter) { return List.of(); }
    @Override public List<ProxyWebSocketMessage> webSocketHistory() { return List.of(); }
    @Override public List<ProxyWebSocketMessage> webSocketHistory(ProxyWebSocketHistoryFilter filter) { return List.of(); }

    @Override public Registration registerRequestHandler(ProxyRequestHandler handler) { return new NoopRegistration(); }
    @Override public Registration registerResponseHandler(ProxyResponseHandler handler) { return new NoopRegistration(); }
    @Override public Registration registerWebSocketCreationHandler(ProxyWebSocketCreationHandler handler) { return new NoopRegistration(); }

    private static class NoopRegistration implements Registration {
        @Override public boolean isRegistered() { return false; }
        @Override public void deregister() {}
    }
}
