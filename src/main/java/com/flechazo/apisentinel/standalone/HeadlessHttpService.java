package com.flechazo.apisentinel.standalone;

import burp.api.montoya.http.HttpService;

/**
 * Headless {@link HttpService} — replaces Burp's ObjectFactoryLocator-based
 * implementation which returns null without a Burp instance.
 */
public class HeadlessHttpService implements HttpService {
    private final String host;
    private final int port;
    private final boolean secure;

    public HeadlessHttpService(String host, int port, boolean secure) {
        this.host = host;
        this.port = port;
        this.secure = secure;
    }

    @Override public String host() { return host; }
    @Override public int port() { return port; }
    @Override public boolean secure() { return secure; }
    @Override public String ipAddress() { return host; }
    @Override public String toString() { return (secure ? "https" : "http") + "://" + host + ":" + port; }
}
