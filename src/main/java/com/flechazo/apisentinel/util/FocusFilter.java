package com.flechazo.apisentinel.util;

public final class FocusFilter {

    private FocusFilter() {}

    /** Global non-business method filter (CORS preflight OPTIONS, HEAD). */
    public static boolean isExcludedMethod(String method, String excludeMethods) {
        if (excludeMethods == null || excludeMethods.isEmpty()) return false;
        for (String em : excludeMethods.split(",")) {
            if (method.equalsIgnoreCase(em.trim())) return true;
        }
        return false;
    }

    /** Check if a host matches any excluded domain (supports {@code *} wildcards).
     *  Case-insensitive. {@code *.firefox.com} matches {@code detectportal.firefox.com}
     *  but not {@code firefox.com}. A bare {@code firefox.com} matches any host
     *  containing that suffix. */
    public static boolean isExcludedDomain(String host, String excludeDomains) {
        if (host == null || host.isEmpty() || excludeDomains == null || excludeDomains.isEmpty()) {
            return false;
        }
        String h = host.toLowerCase(java.util.Locale.ROOT);
        for (String ed : excludeDomains.split(",")) {
            String d = ed.trim().toLowerCase(java.util.Locale.ROOT);
            if (d.isEmpty()) continue;
            if (d.startsWith("*.")) {
                // Wildcard subdomain: *.firefox.com matches x.firefox.com but not firefox.com
                String suffix = d.substring(1); // ".firefox.com"
                if (h.endsWith(suffix) || h.equals(d.substring(2))) return true;
            } else if (d.endsWith(".*")) {
                // Wildcard TLD: firefox.* matches firefox.com, firefox.org etc.
                String prefix = d.substring(0, d.length() - 2);
                if (h.equals(prefix) || h.startsWith(prefix + ".")) return true;
            } else {
                // Exact or suffix match
                if (h.equals(d) || h.endsWith("." + d)) return true;
            }
        }
        return false;
    }
}
