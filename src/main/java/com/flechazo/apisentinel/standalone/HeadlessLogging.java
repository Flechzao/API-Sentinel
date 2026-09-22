package com.flechazo.apisentinel.standalone;

import burp.api.montoya.logging.Logging;

import java.io.PrintStream;

/**
 * Headless {@link Logging} — logs to stdout/stderr instead of Burp's UI.
 */
public class HeadlessLogging implements Logging {

    @Override public PrintStream output() { return System.out; }
    @Override public PrintStream error() { return System.err; }

    @Override public void logToOutput(String msg) { System.out.println("[INFO] " + msg); }
    @Override public void logToOutput(Object obj) { System.out.println("[INFO] " + obj); }
    @Override public void logToError(String msg) { System.err.println("[ERROR] " + msg); }
    @Override public void logToError(String msg, Throwable t) {
        System.err.println("[ERROR] " + msg);
        if (t != null) t.printStackTrace(System.err);
    }
    @Override public void logToError(Throwable t) { if (t != null) t.printStackTrace(System.err); }
    @Override public void raiseDebugEvent(String msg) { System.out.println("[DEBUG] " + msg); }
    @Override public void raiseInfoEvent(String msg) { System.out.println("[INFO] " + msg); }
    @Override public void raiseErrorEvent(String msg) { System.err.println("[ERROR] " + msg); }
    @Override public void raiseCriticalEvent(String msg) { System.err.println("[CRITICAL] " + msg); }
}
