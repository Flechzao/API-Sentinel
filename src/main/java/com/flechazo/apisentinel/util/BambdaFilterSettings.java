package com.flechazo.apisentinel.util;

import com.flechazo.apisentinel.config.AppPaths;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Snapshot of the standalone Bambda builder's filter configuration — a Java
 * port of Bambda++'s {@code FilterSettings}. Serialized to JSON for save/load.
 * Defaults mirror the original plugin's initial UI state.
 *
 * <p>Domain exclusion list is loaded from an external config file
 * ({@code ~/.api-sentinel/bambda-domains.txt}) when available, so
 * company-specific noise domains don't need to be hardcoded in source.
 * A minimal public default is used if the file is not present.
 */
public class BambdaFilterSettings {

    public boolean filterMethodEnabled = true;
    /** HTTP methods to EXCLUDE. Default: everything except GET/POST/PUT/DELETE. */
    public List<String> methods = new ArrayList<>(List.of("HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"));

    public boolean filterDomainEnabled = true;
    /** Comma-separated domains to exclude (wildcards allowed).
     *  Loaded from {@code ~/.api-sentinel/bambda-domains.txt} if present;
     *  otherwise falls back to a minimal public noise list. */
    public String domains = loadDefaultDomains();

    public boolean filterKeywordsEnabled = false;
    public String keywords = "login,com";

    public boolean filterExcludeKeywordsEnabled = true;
    public String excludeKeywords = "interna,firefox,google,baidu,/api/collect/dwcookie,/g/collect,stripe";

    /** "Show only highlighted items". */
    public boolean highlightEnabled = false;
    public boolean filterInScope = false;
    public boolean filterHasResponse = true;
    public boolean filterParameterized = false;

    /** Selected MIME tags (subset of the 8 → active filter). */
    public List<String> mimeTypes = new ArrayList<>(List.of("HTML", "Script", "XML", "Other text", "Flash"));
    /** Selected status bands (subset of the 4 → active filter). */
    public List<String> statusCodes = new ArrayList<>(List.of(
            "2xx [success]", "3xx [redirection]", "4xx [request error]", "5xx [server error]"));

    public boolean searchFilterEnabled = false;
    public String searchTerm = "";
    public boolean searchRegex = false;
    public boolean searchCaseSensitive = false;
    public boolean searchNegative = false;

    public boolean showOnlyExtEnabled = false;
    public String showOnlyExt = "asp,aspx,jsp,php";
    public boolean hideExtEnabled = true;
    public String hideExt = "js,gif,jpg,png,css";

    public boolean filterNotesOnly = false;
    public String listenerPort = "";

    /** All MIME tags the UI offers (order matters for "full set" detection). */
    public static final List<String> ALL_MIME = List.of(
            "HTML", "Script", "XML", "CSS", "Other text", "Images", "Flash", "Other binary");
    /** All status bands the UI offers. */
    public static final List<String> ALL_STATUS = List.of(
            "2xx [success]", "3xx [redirection]", "4xx [request error]", "5xx [server error]");
    /** All HTTP methods the UI offers. */
    public static final List<String> ALL_METHODS = List.of(
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT");

    // ================================================================
    // Domain filter loading
    // ================================================================

    /** Minimal public default: common browser/CDN noise that any user would
     *  want filtered. Company-specific domains go in the external config file. */
    private static final String FALLBACK_DOMAINS =
            "detectportal.firefox.com,getpocket.cdn.mozilla.net,aus5.mozilla.org,"
            + "safebrowsing.googleapis.com,contile.services.mozilla.com,sb.firefox.com.cn,"
            + "firefox.settings.services.mozilla.com,incoming.telemetry.mozilla.org,"
            + "push.services.mozilla.com,content-signature-2.cdn.mozilla.net,addons.firefox.com.cn,"
            + "versioncheck-bg.addons.mozilla.org,www.google-analytics.com,"
            + "hm.baidu.com,fclog.baidu.com,ads.mozilla.org,"
            + "firefox-settings-attachments.cdn.mozilla.net";

    /**
     * Load the domain exclusion list from {@code ~/.api-sentinel/bambda-domains.txt}.
     * The file is a single line of comma-separated domains (wildcards allowed).
     * Falls back to {@link #FALLBACK_DOMAINS} if the file is absent or unreadable.
     */
    private static String loadDefaultDomains() {
        try {
            Path p = AppPaths.resolve("bambda-domains.txt");
            if (Files.exists(p)) {
                String content = Files.readString(p).trim();
                if (!content.isEmpty()) {
                    return content;
                }
            }
        } catch (Exception ignored) {
            // Config not available yet (e.g., during early init) — use fallback
        }
        return FALLBACK_DOMAINS;
    }
}
