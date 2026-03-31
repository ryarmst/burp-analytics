package burp.analytics.matcher;

import burp.analytics.data.ServiceDefinition;

import java.util.Objects;

public final class MatchResult {

    private final ServiceDefinition service;
    private final String matchedPattern;

    public MatchResult(ServiceDefinition service, String matchedPattern) {
        this.service = Objects.requireNonNull(service);
        this.matchedPattern = matchedPattern != null ? matchedPattern : "";
    }

    public ServiceDefinition getService() {
        return service;
    }

    public String getMatchedPattern() {
        return matchedPattern;
    }
}
