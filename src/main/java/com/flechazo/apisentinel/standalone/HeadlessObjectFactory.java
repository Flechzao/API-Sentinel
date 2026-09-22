package com.flechazo.apisentinel.standalone;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Initializes Montoya's {@link ObjectFactoryLocator#FACTORY} with a headless
 * implementation. Uses dynamic proxies throughout so we don't implement 161+
 * methods manually.
 *
 * <p>Call {@link #install()} once at CLI startup.
 */
public final class HeadlessObjectFactory {

    private HeadlessObjectFactory() {}

    public static void install() {
        if (ObjectFactoryLocator.FACTORY != null) return;

        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                MontoyaObjectFactory.class.getClassLoader(),
                new Class<?>[]{MontoyaObjectFactory.class},
                new FactoryHandler());
    }

    static class FactoryHandler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            // Implement only the factory methods we actually use
            return switch (name) {
                case "httpService" -> {
                    if (args != null && args.length >= 1) {
                        String host = (String) args[0];
                        boolean secure = args.length >= 2 && args.length <= 3
                                ? (args.length == 2 ? (Boolean) args[1] : false)
                                : (args.length >= 3 ? (Boolean) args[2] : false);
                        int port = args.length >= 3 ? (Integer) args[1] : (secure ? 443 : 80);
                        yield new HeadlessHttpService(host, port, secure);
                    }
                    yield null;
                }
                case "httpRequest" -> {
                    if (args == null || args.length == 0) {
                        yield createRequestProxy(null, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
                    }
                    if (args.length == 1 && args[0] instanceof String raw) {
                        yield createRequestProxy(null, raw);
                    }
                    if (args.length == 1 && args[0] instanceof ByteArray ba) {
                        yield createRequestProxy(null, new String(ba.getBytes(), StandardCharsets.UTF_8));
                    }
                    if (args.length == 2 && args[0] instanceof HttpService svc) {
                        String raw = args[1] instanceof String s ? s
                                : new String(((ByteArray) args[1]).getBytes(), StandardCharsets.UTF_8);
                        yield createRequestProxy(svc, raw);
                    }
                    yield null;
                }
                case "httpResponse" -> {
                    if (args == null || args.length == 0) {
                        yield createResponseProxy("HTTP/1.1 200 OK\r\n\r\n");
                    }
                    if (args.length >= 1) {
                        String raw = args[0] instanceof String s ? s
                                : new String(((ByteArray) args[0]).getBytes(), StandardCharsets.UTF_8);
                        yield createResponseProxy(raw);
                    }
                    yield null;
                }
                case "httpRequestResponse" -> {
                    if (args != null && args.length == 2) {
                        yield HeadlessHttpRequestResponse.of(
                                (HttpRequest) args[0], (HttpResponse) args[1]);
                    }
                    yield null;
                }
                case "httpHeader" -> {
                    if (args != null && args.length == 2) {
                        yield createHeaderProxy((String) args[0], (String) args[1]);
                    }
                    yield null;
                }
                default -> null; // All other 155 methods: not needed in CLI mode
            };
        }
    }

    @SuppressWarnings("unchecked")
    static HttpRequest createRequestProxy(HttpService service, String raw) {
        String[] parts = raw.split("\r\n\r\n", 2);
        String headerSection = parts[0];
        String body = parts.length > 1 ? parts[1] : "";

        String[] headerLines = headerSection.split("\r\n");
        String requestLine = headerLines[0];
        String[] reqParts = requestLine.split(" ", 3);
        String method = reqParts.length > 0 ? reqParts[0] : "GET";
        String path = reqParts.length > 1 ? reqParts[1] : "/";

        List<HttpHeader> headers = new ArrayList<>();
        for (int i = 1; i < headerLines.length; i++) {
            int colon = headerLines[i].indexOf(':');
            if (colon > 0) {
                headers.add(createHeaderProxy(
                        headerLines[i].substring(0, colon).trim(),
                        headerLines[i].substring(colon + 1).trim()));
            }
        }

        final HttpService fService = service;
        final String fMethod = method, fPath = path, fBody = body, fRaw = raw;
        final List<HttpHeader> fHeaders = headers;

        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "httpService" -> fService;
                    case "method" -> fMethod;
                    case "path" -> fPath;
                    case "url" -> fService != null
                            ? (fService.secure() ? "https" : "http") + "://" + fService.host()
                              + ":" + fService.port() + fPath : fPath;
                    case "bodyToString" -> fBody;
                    case "headers" -> fHeaders;
                    case "body" -> ByteArray.byteArray(fBody.getBytes(StandardCharsets.UTF_8));
                    case "toString" -> fRaw;
                    case "hashCode" -> fRaw.hashCode();
                    case "equals" -> args != null && args.length > 0 && args[0] != null
                            && args[0].toString().equals(fRaw);
                    default -> null;
                });
    }

    @SuppressWarnings("unchecked")
    static HttpResponse createResponseProxy(String raw) {
        String[] parts = raw.split("\r\n\r\n", 2);
        String headerSection = parts[0];
        String body = parts.length > 1 ? parts[1] : "";

        String[] headerLines = headerSection.split("\r\n");
        int statusCode = 200;
        try {
            String[] sp = headerLines[0].split(" ");
            if (sp.length >= 2) statusCode = Integer.parseInt(sp[1]);
        } catch (Exception ignored) {}

        List<HttpHeader> headers = new ArrayList<>();
        for (int i = 1; i < headerLines.length; i++) {
            int colon = headerLines[i].indexOf(':');
            if (colon > 0) {
                headers.add(createHeaderProxy(
                        headerLines[i].substring(0, colon).trim(),
                        headerLines[i].substring(colon + 1).trim()));
            }
        }

        final int fCode = statusCode;
        final String fBody = body, fRaw = raw;
        final List<HttpHeader> fHeaders = headers;

        return (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "statusCode" -> (short) fCode;
                    case "bodyToString" -> fBody;
                    case "body" -> ByteArray.byteArray(fBody.getBytes(StandardCharsets.UTF_8));
                    case "headers" -> fHeaders;
                    case "toString" -> fRaw;
                    case "hashCode" -> fRaw.hashCode();
                    case "equals" -> args != null && args.length > 0 && args[0] != null
                            && args[0].toString().equals(fRaw);
                    default -> null;
                });
    }

    @SuppressWarnings("unchecked")
    static HttpHeader createHeaderProxy(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
                HttpHeader.class.getClassLoader(),
                new Class<?>[]{HttpHeader.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "name" -> name;
                    case "value" -> value;
                    case "toString" -> name + ": " + value;
                    case "hashCode" -> (name + ": " + value).hashCode();
                    case "equals" -> args != null && args.length > 0 && args[0] != null
                            && args[0].toString().equals(name + ": " + value);
                    default -> null;
                });
    }
}
