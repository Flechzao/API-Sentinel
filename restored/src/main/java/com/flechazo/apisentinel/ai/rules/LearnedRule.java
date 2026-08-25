package com.flechazo.apisentinel.ai.rules;

import java.util.concurrent.atomic.AtomicInteger;

public class LearnedRule {

    private String name;
    private String pattern;
    private String riskLevel;
    private String description;
    private String sourceApiPath;
    private String vulnType;
    private long createdAt;
    private transient AtomicInteger matchCountAtomic;
    private int matchCount;

    public LearnedRule() {
        this.matchCountAtomic = new AtomicInteger(0);
    }

    public LearnedRule(String name, String pattern, String riskLevel,
                       String description, String sourceApiPath, String vulnType) {
        this.name = name;
        this.pattern = pattern;
        this.riskLevel = riskLevel;
        this.description = description;
        this.sourceApiPath = sourceApiPath;
        this.vulnType = vulnType;
        this.createdAt = System.currentTimeMillis();
        this.matchCount = 0;
        this.matchCountAtomic = new AtomicInteger(0);
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getPattern() { return pattern; }
    public void setPattern(String pattern) { this.pattern = pattern; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSourceApiPath() { return sourceApiPath; }
    public void setSourceApiPath(String sourceApiPath) { this.sourceApiPath = sourceApiPath; }

    public String getVulnType() { return vulnType; }
    public void setVulnType(String vulnType) { this.vulnType = vulnType; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public int getMatchCount() {
        ensureAtomic();
        return matchCountAtomic.get();
    }

    public void setMatchCount(int matchCount) {
        this.matchCount = matchCount;
        ensureAtomic();
        this.matchCountAtomic.set(matchCount);
    }

    public void incrementMatchCount() {
        ensureAtomic();
        this.matchCount = matchCountAtomic.incrementAndGet();
    }

    /**
     * Sync the atomic counter back to the plain field before serialization.
     * Gson skips the transient AtomicInteger, so without this the persisted
     * matchCount can be stale relative to in-memory increments.
     */
    public void syncMatchCount() {
        ensureAtomic();
        this.matchCount = matchCountAtomic.get();
    }

    private void ensureAtomic() {
        if (matchCountAtomic == null) {
            matchCountAtomic = new AtomicInteger(matchCount);
        }
    }

    @Override
    public String toString() {
        return String.format("LearnedRule{name='%s', vulnType='%s', risk='%s', pattern='%s'}",
                name, vulnType, riskLevel, pattern);
    }
}
