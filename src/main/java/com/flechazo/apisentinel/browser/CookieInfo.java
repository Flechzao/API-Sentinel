package com.flechazo.apisentinel.browser;

/**
 * Cookie information extracted from browser session.
 */
public class CookieInfo {
    
    /** Cookie name */
    public String name;
    
    /** Cookie value */
    public String value;
    
    /** Cookie domain */
    public String domain;
    
    /** Cookie path */
    public String path;
    
    @Override
    public String toString() {
        return name + "=" + value + " (domain=" + domain + ", path=" + path + ")";
    }
}
