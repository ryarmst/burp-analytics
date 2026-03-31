package burp.analytics.handler;

import burp.analytics.MatchStrings;
import burp.analytics.issues.AnalyticsIssueService;
import burp.analytics.matcher.AnalyticsMatcher;
import burp.analytics.matcher.MatchResult;
import burp.analytics.session.SessionMatchStore;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import javax.swing.SwingUtilities;
import java.util.Optional;

public final class AnalyticsHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final AnalyticsMatcher matcher;
    private final SessionMatchStore sessionMatches;
    private final AnalyticsIssueService issueService;
    private final Runnable onSessionUpdate;

    public AnalyticsHttpHandler(
            MontoyaApi api,
            AnalyticsMatcher matcher,
            SessionMatchStore sessionMatches,
            AnalyticsIssueService issueService,
            Runnable onSessionUpdate) {
        this.api = api;
        this.matcher = matcher;
        this.sessionMatches = sessionMatches;
        this.issueService = issueService;
        this.onSessionUpdate = onSessionUpdate != null ? onSessionUpdate : () -> {};
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            if (!responseReceived.toolSource().isFromTool(ToolType.PROXY)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            var initiating = responseReceived.initiatingRequest();
            Optional<MatchResult> m = matcher.matchHttpRequest(initiating);
            if (m.isEmpty()) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            MatchResult mr = m.get();
            var svc = mr.getService();
            String fqdn = initiating.httpService().host();
            String target = MatchStrings.fromRequest(initiating);
            HttpRequestResponse evidence =
                    HttpRequestResponse.httpRequestResponse(
                            initiating, responseReceived, responseReceived.annotations());
            boolean firstFqdn =
                    sessionMatches.recordIfNewFqdn(
                            fqdn, svc.getId(), svc.getName(), mr.getMatchedPattern(), target, evidence);
            if (firstFqdn) {
                issueService.raiseInformationalIssue(svc, mr.getMatchedPattern(), evidence);
            }
            SwingUtilities.invokeLater(onSessionUpdate);
        } catch (Exception e) {
            api.logging().logToError("Analytics: HTTP response handler error: " + e.getMessage());
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
