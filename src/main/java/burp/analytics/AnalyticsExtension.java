package burp.analytics;

import burp.analytics.handler.AnalyticsHttpHandler;
import burp.analytics.issues.AnalyticsIssueService;
import burp.analytics.matcher.AnalyticsMatcher;
import burp.analytics.session.SessionMatchStore;
import burp.analytics.ui.AnalyticsContextMenuProvider;
import burp.analytics.ui.AnalyticsController;
import burp.analytics.ui.AnalyticsSuiteTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public final class AnalyticsExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Analytics Database");

        AnalyticsMatcher matcher = new AnalyticsMatcher();
        SessionMatchStore sessionMatches = new SessionMatchStore();
        AnalyticsController controller = new AnalyticsController(matcher);
        AnalyticsIssueService issueService = new AnalyticsIssueService(api);

        AnalyticsSuiteTab tab =
                new AnalyticsSuiteTab(api, api.persistence().preferences(), controller, sessionMatches);

        AnalyticsHttpHandler httpHandler =
                new AnalyticsHttpHandler(api, matcher, sessionMatches, issueService, tab::refreshAfterSessionMatch);
        api.http().registerHttpHandler(httpHandler);

        api.userInterface().registerSuiteTab("Analytics DB", tab);
        api.userInterface().applyThemeToComponent(tab);
        api.userInterface().registerContextMenuItemsProvider(new AnalyticsContextMenuProvider(tab));
    }
}
