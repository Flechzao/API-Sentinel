package com.flechazo.apisentinel.config;

import java.util.ArrayList;
import java.util.List;

public class CodeRepo {
    private String name;
    private String path;
    private List<String> domains;
    private transient boolean indexed;
    private transient int routeCount;
    /** P0-12: non-null when the last indexing attempt failed; cleared on
     *  success. Lets the UI and the analysis code tell "indexed and
     *  healthy" apart from "we tried and couldn't" rather than reading
     *  indexed==false as "hasn't been tried yet". */
    private transient String indexError;

    public CodeRepo() {
        this.name = "";
        this.path = "";
        this.domains = new ArrayList<>();
    }

    public CodeRepo(String name, String path, List<String> domains) {
        this.name = name;
        this.path = path;
        this.domains = domains != null ? new ArrayList<>(domains) : new ArrayList<>();
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public List<String> getDomains() { return domains; }
    public void setDomains(List<String> domains) { this.domains = domains != null ? domains : new ArrayList<>(); }

    public boolean isIndexed() { return indexed; }
    public void setIndexed(boolean indexed) { this.indexed = indexed; }

    public int getRouteCount() { return routeCount; }
    public void setRouteCount(int routeCount) { this.routeCount = routeCount; }

    /** P0-12: the last indexing error message, or null when the repo is
     *  either unindexed-but-untried or indexed-and-healthy. Consumers
     *  that show repo status in the UI should render the message
     *  verbatim rather than a generic "not indexed" label. */
    public String getIndexError() { return indexError; }
    public void setIndexError(String indexError) { this.indexError = indexError; }

    public boolean matchesDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase();
        String hostOnly = lower.contains(":") ? lower.substring(0, lower.lastIndexOf(':')) : lower;
        for (String d : domains) {
            String dl = d.toLowerCase().trim();
            if (dl.equals(lower) || dl.equals(hostOnly)) return true;
        }
        return false;
    }

    @Override
    public String toString() {
        return name + " (" + path + ") -> " + domains;
    }
}
