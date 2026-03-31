package burp.analytics.issues;

import burp.analytics.data.ServiceDefinition;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Collections;

public final class AnalyticsIssueService {

    private final MontoyaApi api;

    public AnalyticsIssueService(MontoyaApi api) {
        this.api = api;
    }

    public void raiseInformationalIssue(ServiceDefinition service, String matchedPattern, HttpRequestResponse evidence) {
        if (service == null || evidence == null) {
            return;
        }
        String name = "Analytics / third-party: " + escapeHtml(service.getName());
        HttpRequest req = evidence.request();
        String baseUrl = EmbeddingIssueUrl.issueBaseUrl(req);
        String detail = buildDetail(service, matchedPattern, req);
        String remediation = "Review testing methodology for this service.";
        AuditIssue issue = AuditIssue.auditIssue(
                name,
                detail,
                remediation,
                baseUrl,
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.CERTAIN,
                "Human-curated analytics or third-party service match.",
                "Adjust TLS pass-through settings as appropriate for your engagement.",
                AuditIssueSeverity.INFORMATION,
                Collections.singletonList(evidence)
        );
        api.siteMap().add(issue);
    }

    private static String buildDetail(ServiceDefinition service, String matchedPattern, HttpRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p><b>Service</b>: ").append(escapeHtml(service.getName())).append("</p>");
        sb.append("<p><b>Description</b>: ").append(escapeHtml(service.getDescription())).append("</p>");
        sb.append("<p><b>Matched pattern</b>: <code>").append(escapeHtml(matchedPattern)).append("</code></p>");
        sb.append("<p><b>Testing methodology</b>: ").append(escapeHtml(service.getMethodology())).append("</p>");
        String embedding = EmbeddingIssueUrl.issueBaseUrl(request);
        String thirdParty;
        try {
            thirdParty = request.url();
        } catch (Exception e) {
            thirdParty = "";
        }
        sb.append("<p><b>Reported against (embedding site)</b>: ").append(escapeHtml(embedding)).append("</p>");
        if (!thirdParty.isEmpty() && !thirdParty.equals(embedding)) {
            sb.append("<p><b>Third-party request</b>: ").append(escapeHtml(thirdParty)).append("</p>");
        }
        return sb.toString();
    }

    private static String escapeHtml(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
