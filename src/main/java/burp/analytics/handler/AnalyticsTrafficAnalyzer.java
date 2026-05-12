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
        return recordIfMatch(request, item.response(), item.annotations(), raiseIssue);
    }

    public enum MatchRecordStatus {
        NO_MATCH,
        DUPLICATE,
        RECORDED
    }
}
