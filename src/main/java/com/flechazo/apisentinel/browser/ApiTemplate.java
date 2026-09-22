package com.flechazo.apisentinel.browser;

import java.util.List;
import java.util.Map;

/**
 * Template for an API endpoint extracted from browser exploration.
 * Contains URL, headers, body template, and required parameters.
 */
public class ApiTemplate {
    
    /** HTTP method (GET, POST, PUT, DELETE, etc.) */
    public String method;
    
    /** Full URL (e.g., "https://app.example.com/api/roles") */
    public String url;
    
    /** Authentication-related headers (Cookie, Authorization, etc.) */
    public Map<String, String> authHeaders;
    
    /** Content-Type header value */
    public String contentType;
    
    /** Body template with placeholders (e.g., {"roleName": "${roleName}"}) */
    public String bodyTemplate;
    
    /** List of required parameter names extracted from body */
    public List<String> requiredParams;
    
    /**
     * Construct a concrete request body by replacing placeholders with values.
     * 
     * @param params Map of parameter name → value
     * @return Concrete request body
     */
    public String buildBody(Map<String, String> params) {
        if (bodyTemplate == null) {
            return null;
        }
        
        String body = bodyTemplate;
        for (Map.Entry<String, String> param : params.entrySet()) {
            String placeholder = "${" + param.getKey() + "}";
            body = body.replace(placeholder, param.getValue());
        }
        
        return body;
    }
    
    /**
     * Check if all required parameters are provided.
     * 
     * @param params Map of parameter name → value
     * @return true if all required params are present
     */
    public boolean hasAllRequiredParams(Map<String, String> params) {
        if (requiredParams == null) {
            return true;
        }
        
        for (String param : requiredParams) {
            if (!params.containsKey(param)) {
                return false;
            }
        }
        
        return true;
    }
    
    @Override
    public String toString() {
        return "ApiTemplate{" +
            "method='" + method + '\'' +
            ", url='" + url + '\'' +
            ", requiredParams=" + requiredParams +
            '}';
    }
}
