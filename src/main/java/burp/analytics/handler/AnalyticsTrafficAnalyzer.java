package burp.analytics.handler;

import burp.analytics.MatchStrings;
import burp.analytics.issues.AnalyticsIssueService;
import burp.analytics.matcher.AnalyticsMatcher;
import burp.analytics.matcher.MatchResult;
import burp.analytics.session.SessionMatchStore;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.Optional;

public final class AnalyticsTrafficAnalyzer {

    private final AnalyticsMatcher matcher;
    private final SessionMatchStore sessionMatches;
    private final AnalyticsIssueService issueService;

    public AnalyticsTrafficAnalyzer(
            AnalyticsMatcher matcher, SessionMatchStore sessionMatches, AnalyticsIssueService issueService) {
        this.matcher = matcher;
        this.sessionMatches = sessionMatches;
        this.issueService = issueService;
    }

    public MatchRecordStatus recordIfMatch(
            HttpRequest request, HttpResponse response, Annotations annotations, boolean raiseIssue) {
        Optional<MatchResult> match = matcher.matchHttpRequest(request);
        if (match.isEmpty()) {
            return MatchRecordStatus.NO_MATCH;
        }
        MatchResult result = match.get();
        var service = result.getService();
        String fqdn = request.httpService().host();
        String target = MatchStrings.fromRequest(request);
        HttpRequestResponse evidence = HttpRequestResponse.httpRequestResponse(request, response, annotations);
        boolean recorded =
                sessionMatches.recordIfNewFqdnService(
                        fqdn, service.getId(), service.getName(), result.getMatchedPattern(), target, evidence);
        if (!recorded) {
            return MatchRecordStatus.DUPLICATE;
        }
        if (raiseIssue) {
            issueService.raiseInformationalIssue(service, result.getMatchedPattern(), evidence);
        }
        return MatchRecordStatus.RECORDED;
    }

    public MatchRecordStatus recordProxyHistoryItem(ProxyHttpRequestResponse item, boolean raiseIssue) {
        return recordProxyHistoryItem(item, raiseIssue, true);
    }

    /**
     * When {@code matchResponseBody} is true, applies the same service regex patterns to a bounded
     * UTF-8 preview of the response body if request-based matching misses (manual history scan).
     */
    public MatchRecordStatus recordProxyHistoryItem(
            ProxyHttpRequestResponse item, boolean raiseIssue, boolean matchResponseBody) {
        if (item == null) {
            return MatchRecordStatus.NO_MATCH;
        }
        HttpRequest request = item.finalRequest();
        if (request == null) {
            request = item.request();
        }
        if (request == null) {
            return MatchRecordStatus.NO_MATCH;
        }
        return recordHistoryScanMatch(request, item.response(), item.annotations(), raiseIssue, matchResponseBody);
    }

    private MatchRecordStatus recordHistoryScanMatch(
            HttpRequest request,
            HttpResponse response,
            Annotations annotations,
            boolean raiseIssue,
            boolean matchResponseBody) {
        Optional<MatchResult> match = matcher.matchHttpRequest(request);
        String matchTarget = MatchStrings.fromRequest(request);
        if (match.isEmpty() && matchResponseBody) {
            String bodyText = ResponseBodyText.utf8Preview(response, ResponseBodyText.DEFAULT_MAX_BYTES);
            if (!bodyText.isEmpty()) {
                match = matcher.match(bodyText);
                if (match.isPresent()) {
                    matchTarget = "(response body) " + matchTarget;
                }
            }
        }
        if (match.isEmpty()) {
            return MatchRecordStatus.NO_MATCH;
        }
        MatchResult result = match.orElseThrow();
        var service = result.getService();
        String fqdn = request.httpService().host();
        HttpRequestResponse evidence = HttpRequestResponse.httpRequestResponse(request, response, annotations);
        boolean recorded =
                sessionMatches.recordIfNewFqdnService(
                        fqdn,
                        service.getId(),
                        service.getName(),
                        result.getMatchedPattern(),
                        matchTarget,
                        evidence);
        if (!recorded) {
            return MatchRecordStatus.DUPLICATE;
        }
        if (raiseIssue) {
            issueService.raiseInformationalIssue(service, result.getMatchedPattern(), evidence);
        }
        return MatchRecordStatus.RECORDED;
    }

    public enum MatchRecordStatus {
        NO_MATCH,
        DUPLICATE,
        RECORDED
    }
}
