package com.flechazo.apisentinel.standalone;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.Ai;
import burp.api.montoya.bambda.Bambda;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.comparer.Comparer;
import burp.api.montoya.decoder.Decoder;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.http.Http;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.organizer.Organizer;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.project.Project;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.utilities.Utilities;
import burp.api.montoya.websocket.WebSockets;

/**
 * Minimal headless implementation of {@link MontoyaApi} for CLI mode.
 *
 * <p>Only {@link #http()} and {@link #logging()} are functional; all other
 * methods return null (they are UI/Burp-specific features not needed in
 * standalone mode). The existing tools check for null returns gracefully.
 */
public class HeadlessMontoyaApi implements MontoyaApi {

    private final Http http;
    private final Logging logging;

    public HeadlessMontoyaApi() {
        this.http = new HeadlessHttp();
        this.logging = new HeadlessLogging();
    }

    @Override public Http http() { return http; }
    @Override public Logging logging() { return logging; }
    @Override public Proxy proxy() { return new HeadlessProxy(); }

    // The following return null — not needed in CLI mode. Tools that use
    // them (e.g. Intruder payload generator, Scanner) are Burp-only features
    // that are simply not invoked in standalone mode.
    @Override public Ai ai() { return null; }
    @Override public Bambda bambda() { return null; }
    @Override public BurpSuite burpSuite() { return null; }
    @Override public Collaborator collaborator() { return null; }
    @Override public Comparer comparer() { return null; }
    @Override public Decoder decoder() { return null; }
    @Override public Extension extension() { return null; }
    @Override public Intruder intruder() { return null; }
    @Override public Organizer organizer() { return null; }
    @Override public Persistence persistence() { return null; }
    @Override public Project project() { return null; }
    @Override public Repeater repeater() { return null; }
    @Override public Scanner scanner() { return null; }
    @Override public Scope scope() { return null; }
    @Override public SiteMap siteMap() { return null; }
    @Override public UserInterface userInterface() { return null; }
    @Override public Utilities utilities() { return null; }
    @Override public WebSockets websockets() { return null; }
}
