package com.flechazo.apisentinel.matching;

import com.flechazo.apisentinel.model.ApiEntry;

import java.util.Collection;
import java.util.List;

public interface MatchEngine {

    List<ApiEntry> match(String urlPath, String requestBody);

    void rebuild(Collection<ApiEntry> entries);

    void addEntry(ApiEntry entry);

    void removeEntry(String apiPath);
}
