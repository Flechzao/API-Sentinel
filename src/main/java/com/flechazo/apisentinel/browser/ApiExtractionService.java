package com.flechazo.apisentinel.browser;

import com.google.gson.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

/**
 * Service for extracting API templates from browser exploration.
 * Uses agent-browser HAR recording to capture complete request structures.
 */
public class ApiExtractionService {
    
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    
    private final BrowserService browserService;
    private final AgentBrowserCli agentBrowserCli;
    
    public ApiExtractionService(BrowserService browserService) {
        this.browserService = browserService;
        this.agentBrowserCli = new AgentBrowserCli();
    }
    
    /**
     * Extract API template from browser exploration.
     * 
     * @param targetApiPath The API path to explore (e.g., "POST /api/roles")
     * @return ApiTemplate containing URL, headers, body template, and required params
     * @throws IOException If agent-browser commands fail
     */
    public ApiTemplate extractApiTemplate(String targetApiPath) throws IOException {
        // 1. Start HAR recording
        agentBrowserCli.execute("network", "har", "start", "--content", "all");
        
        try {
            // 2. Execute browser exploration (LLM navigates to target API)
            // This is handled by the ExplorationEngine, which calls browser_explore
            // We just need to ensure HAR recording is active during exploration
            
            // 3. Stop HAR recording and export
            File harFile = File.createTempFile("api-extraction-", ".har");
            agentBrowserCli.execute("network", "har", "stop", harFile.getAbsolutePath());
            
            // 4. Parse HAR and extract target API request
            HarEntry entry = findTargetApiEntry(harFile, targetApiPath);
            if (entry == null) {
                throw new IOException("Target API not found in HAR: " + targetApiPath);
            }
            
            // 5. Construct API template
            return buildApiTemplate(entry);
            
        } finally {
            // Cleanup temp file
            // Note: Keep HAR file for debugging if needed
        }
    }
    
    /**
     * Extract authentication credentials from current browser session.
     * 
     * @return AuthContext containing cookies and tokens
     * @throws IOException If agent-browser commands fail
     */
    public AuthContext extractAuthContext() throws IOException {
        // 1. Get cookies
        String cookiesJson = agentBrowserCli.execute("cookies", "--json");
        List<CookieInfo> cookies = parseCookies(cookiesJson);
        
        // 2. Get localStorage (for JWT tokens)
        String storageJson = agentBrowserCli.execute("storage", "local", "--json");
        Map<String, String> localStorage = parseLocalStorage(storageJson);
        
        // 3. Extract bearer token from Authorization header (if present)
        String bearerToken = extractBearerToken(localStorage);
        
        return new AuthContext(cookies, localStorage, bearerToken);
    }
    
    /**
     * Capture request templates from network traffic.
     * 
     * @param filter Request filter (e.g., "xhr,fetch", "POST", "2xx")
     * @return List of captured requests
     * @throws IOException If agent-browser commands fail
     */
    public List<CapturedRequest> captureRequests(String filter) throws IOException {
        List<String> args = new ArrayList<>();
        args.add("network");
        args.add("requests");
        
        if (filter != null && !filter.isEmpty()) {
            // Parse filter: "xhr,fetch", "POST", "2xx", etc.
            if (filter.contains(",")) {
                // Resource type filter
                args.add("--type");
                args.add(filter);
            } else if (filter.matches("\\d+xx|\\d{3}")) {
                // Status code filter
                args.add("--status");
                args.add(filter);
            } else if (filter.matches("GET|POST|PUT|DELETE|PATCH")) {
                // HTTP method filter
                args.add("--method");
                args.add(filter);
            }
        }
        
        args.add("--json");
        
        String json = agentBrowserCli.execute(args.toArray(new String[0]));
        return parseCapturedRequests(json);
    }
    
    /**
     * Save request templates to file for later reuse.
     * 
     * @param requests List of captured requests
     * @param outputFile Output file path
     * @throws IOException If file write fails
     */
    public void saveRequestTemplates(List<CapturedRequest> requests, File outputFile) throws IOException {
        JsonObject root = new JsonObject();
        root.addProperty("capturedAt", System.currentTimeMillis());
        root.add("requests", GSON.toJsonTree(requests));
        Files.writeString(outputFile.toPath(), GSON.toJson(root));
    }
    
    /**
     * Load request templates from file.
     * 
     * @param inputFile Input file path
     * @return List of captured requests
     * @throws IOException If file read fails
     */
    public List<CapturedRequest> loadRequestTemplates(File inputFile) throws IOException {
        String content = Files.readString(inputFile.toPath());
        JsonObject root = JsonParser.parseString(content).getAsJsonObject();
        JsonArray requestsArr = root.getAsJsonArray("requests");
        
        List<CapturedRequest> requests = new ArrayList<>();
        for (JsonElement elem : requestsArr) {
            requests.add(GSON.fromJson(elem, CapturedRequest.class));
        }
        return requests;
    }
    
    // ========== Private Methods ==========
    
    private HarEntry findTargetApiEntry(File harFile, String targetApiPath) throws IOException {
        String content = Files.readString(harFile.toPath());
        JsonObject har = JsonParser.parseString(content).getAsJsonObject();
        JsonObject log = har.getAsJsonObject("log");
        JsonArray entries = log != null ? log.getAsJsonArray("entries") : null;
        
        if (entries == null) return null;
        
        // Parse target: "POST /api/roles" → method=POST, path=/api/roles
        String[] parts = targetApiPath.split(" ", 2);
        String targetMethod = parts.length > 1 ? parts[0] : null;
        String targetPath = parts.length > 1 ? parts[1] : parts[0];
        
        for (JsonElement entryElem : entries) {
            JsonObject entry = entryElem.getAsJsonObject();
            JsonObject request = entry.getAsJsonObject("request");
            String method = getStringOrNull(request, "method");
            String url = getStringOrNull(request, "url");
            
            // Check if this entry matches target API
            boolean methodMatch = targetMethod == null || method.equalsIgnoreCase(targetMethod);
            boolean pathMatch = url != null && url.contains(targetPath);
            
            if (methodMatch && pathMatch) {
                return parseHarEntry(entry);
            }
        }
        
        return null;
    }
    
    private HarEntry parseHarEntry(JsonObject entry) {
        JsonObject request = entry.getAsJsonObject("request");
        
        HarEntry harEntry = new HarEntry();
        harEntry.method = getStringOrNull(request, "method");
        harEntry.url = getStringOrNull(request, "url");
        
        // Parse headers
        harEntry.headers = new HashMap<>();
        JsonArray headers = request.getAsJsonArray("headers");
        if (headers != null) {
            for (JsonElement headerElem : headers) {
                JsonObject header = headerElem.getAsJsonObject();
                harEntry.headers.put(
                    getStringOrNull(header, "name"),
                    getStringOrNull(header, "value")
                );
            }
        }
        
        // Parse POST data
        JsonObject postData = request.getAsJsonObject("postData");
        if (postData != null) {
            harEntry.mimeType = getStringOrNull(postData, "mimeType");
            harEntry.body = getStringOrNull(postData, "text");
        }
        
        return harEntry;
    }
    
    private ApiTemplate buildApiTemplate(HarEntry entry) {
        ApiTemplate template = new ApiTemplate();
        template.method = entry.method;
        template.url = entry.url;
        
        // Extract auth-related headers
        template.authHeaders = extractAuthHeaders(entry.headers);
        
        // Extract body template (replace concrete values with placeholders)
        if (entry.body != null && !entry.body.isEmpty()) {
            template.bodyTemplate = extractBodyTemplate(entry.body);
            template.requiredParams = extractRequiredParams(entry.body);
        } else {
            template.bodyTemplate = null;
            template.requiredParams = Collections.emptyList();
        }
        
        // Extract content type
        template.contentType = entry.headers.getOrDefault("Content-Type", "application/json");
        
        return template;
    }
    
    private Map<String, String> extractAuthHeaders(Map<String, String> headers) {
        Map<String, String> authHeaders = new HashMap<>();
        
        // Common auth header patterns
        List<String> authPatterns = Arrays.asList(
            "Cookie",
            "Authorization",
            "X-Auth-Token",
            "X-API-Key",
            "X-CSRF-Token"
        );
        
        for (String headerName : headers.keySet()) {
            for (String pattern : authPatterns) {
                if (headerName.equalsIgnoreCase(pattern)) {
                    authHeaders.put(headerName, headers.get(headerName));
                    break;
                }
            }
        }
        
        return authHeaders;
    }
    
    private String extractBodyTemplate(String body) {
        // Simple template extraction: replace string values with placeholders
        // Example: {"roleName": "Admin"} → {"roleName": "${roleName}"}
        
        // For JSON bodies, parse and replace
        try {
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            return replaceJsonValues(json, "").toString();
        } catch (Exception e) {
            // Not JSON, return as-is
            return body;
        }
    }
    
    private JsonElement replaceJsonValues(JsonElement element, String path) {
        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            JsonObject result = new JsonObject();
            for (Map.Entry<String, JsonElement> field : obj.entrySet()) {
                String fieldPath = path.isEmpty() ? field.getKey() : path + "." + field.getKey();
                result.add(field.getKey(), replaceJsonValues(field.getValue(), fieldPath));
            }
            return result;
        } else if (element.isJsonPrimitive()) {
            JsonPrimitive prim = element.getAsJsonPrimitive();
            String fieldName = path.substring(path.lastIndexOf('.') + 1);
            if (prim.isString() || prim.isNumber()) {
                return new JsonPrimitive("${" + fieldName + "}");
            }
            return element;
        } else if (element.isJsonArray()) {
            // Keep arrays as-is for now
            return element;
        } else {
            return element;
        }
    }
    
    private List<String> extractRequiredParams(String body) {
        List<String> params = new ArrayList<>();
        
        try {
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            extractParamsFromJson(json, "", params);
        } catch (Exception e) {
            // Not JSON, no params
        }
        
        return params;
    }
    
    private void extractParamsFromJson(JsonElement element, String path, List<String> params) {
        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> field : obj.entrySet()) {
                String fieldPath = path.isEmpty() ? field.getKey() : path + "." + field.getKey();
                extractParamsFromJson(field.getValue(), fieldPath, params);
            }
        } else if (element.isJsonPrimitive()) {
            // Leaf node, add to params
            String fieldName = path.substring(path.lastIndexOf('.') + 1);
            params.add(fieldName);
        } else if (element.isJsonArray()) {
            // Array elements
            JsonArray arr = element.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                extractParamsFromJson(arr.get(i), path + "[" + i + "]", params);
            }
        }
    }
    
    private List<CookieInfo> parseCookies(String json) throws IOException {
        JsonArray cookiesArr = JsonParser.parseString(json).getAsJsonArray();
        List<CookieInfo> cookies = new ArrayList<>();
        
        for (JsonElement elem : cookiesArr) {
            JsonObject cookie = elem.getAsJsonObject();
            CookieInfo info = new CookieInfo();
            info.name = getStringOrNull(cookie, "name");
            info.value = getStringOrNull(cookie, "value");
            info.domain = getStringOrNull(cookie, "domain");
            info.path = getStringOrNull(cookie, "path");
            cookies.add(info);
        }
        
        return cookies;
    }
    
    private Map<String, String> parseLocalStorage(String json) throws IOException {
        JsonObject storageObj = JsonParser.parseString(json).getAsJsonObject();
        Map<String, String> storage = new HashMap<>();
        
        for (Map.Entry<String, JsonElement> entry : storageObj.entrySet()) {
            storage.put(entry.getKey(), entry.getValue().getAsString());
        }
        
        return storage;
    }
    
    private String extractBearerToken(Map<String, String> localStorage) {
        // Common localStorage keys for JWT tokens
        List<String> tokenKeys = Arrays.asList(
            "token",
            "access_token",
            "auth_token",
            "jwt",
            "accessToken"
        );
        
        for (String key : tokenKeys) {
            if (localStorage.containsKey(key)) {
                return localStorage.get(key);
            }
        }
        
        return null;
    }
    
    private List<CapturedRequest> parseCapturedRequests(String json) throws IOException {
        JsonArray requestsArr = JsonParser.parseString(json).getAsJsonArray();
        List<CapturedRequest> requests = new ArrayList<>();
        
        for (JsonElement elem : requestsArr) {
            JsonObject reqObj = elem.getAsJsonObject();
            String method = getStringOrNull(reqObj, "method");
            String url = getStringOrNull(reqObj, "url");
            int status = reqObj.has("status") ? reqObj.get("status").getAsInt() : 0;
            
            // Parse headers
            Map<String, String> headers = new HashMap<>();
            JsonObject headersObj = reqObj.getAsJsonObject("headers");
            if (headersObj != null) {
                for (Map.Entry<String, JsonElement> entry : headersObj.entrySet()) {
                    headers.put(entry.getKey(), entry.getValue().getAsString());
                }
            }
            
            // Parse body
            String body = getStringOrNull(reqObj, "body");
            
            requests.add(new CapturedRequest(method, url, headers, body, status, ""));
        }
        
        return requests;
    }
    
    private static String getStringOrNull(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return null;
        }
        return obj.get(key).getAsString();
    }
    
    // ========== Inner Classes ==========
    
    private static class HarEntry {
        String method;
        String url;
        Map<String, String> headers;
        String mimeType;
        String body;
    }
}
