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
}
