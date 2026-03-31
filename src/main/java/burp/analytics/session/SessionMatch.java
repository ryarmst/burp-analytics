package burp.analytics.session;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.Instant;

/** One proxy session row per FQDN. */
public final class SessionMatch {

    private final Instant time;
    private final String fqdn;
    private final String serviceId;
    private final String serviceName;
    private final String matchedPattern;
    private final String matchTarget;
    private final HttpRequestResponse evidence;

    public SessionMatch(
            Instant time,
            String fqdn,
            String serviceId,
            String serviceName,
            String matchedPattern,
            String matchTarget,
            HttpRequestResponse evidence) {
        this.time = time;
        this.fqdn = fqdn;
        this.serviceId = serviceId;
        this.serviceName = serviceName;
        this.matchedPattern = matchedPattern;
        this.matchTarget = matchTarget;
        this.evidence = evidence;
    }

    public Instant getTime() {
        return time;
    }

    public String getFqdn() {
        return fqdn;
    }

    public String getServiceId() {
        return serviceId;
    }

    public String getServiceName() {
        return serviceName;
    }

    public String getMatchedPattern() {
        return matchedPattern;
    }

    public String getMatchTarget() {
        return matchTarget;
    }

    public HttpRequestResponse getEvidence() {
        return evidence;
    }
}
