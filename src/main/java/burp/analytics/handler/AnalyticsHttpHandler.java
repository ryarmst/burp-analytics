package burp.analytics.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import javax.swing.SwingUtilities;

public final class AnalyticsHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final AnalyticsTrafficAnalyzer trafficAnalyzer;
    private final Runnable onSessionUpdate;

    public AnalyticsHttpHandler(
            MontoyaApi api,
            AnalyticsTrafficAnalyzer trafficAnalyzer,
            Runnable onSessionUpdate) {
        this.api = api;
        this.trafficAnalyzer = trafficAnalyzer;
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
            AnalyticsTrafficAnalyzer.MatchRecordStatus status =
                    trafficAnalyzer.recordIfMatch(
                            responseReceived.initiatingRequest(),
                            responseReceived,
                            responseReceived.annotations(),
                            true);
            if (status == AnalyticsTrafficAnalyzer.MatchRecordStatus.RECORDED) {
                SwingUtilities.invokeLater(onSessionUpdate);
            }
        } catch (Exception e) {
            api.logging().logToError("Analytics: HTTP response handler error: " + e.getMessage());
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
