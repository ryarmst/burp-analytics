package burp.analytics.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/** Context menu: create service from selected request. */
public final class AnalyticsContextMenuProvider implements ContextMenuItemsProvider {

    private final AnalyticsSuiteTab suiteTab;

    public AnalyticsContextMenuProvider(AnalyticsSuiteTab suiteTab) {
        this.suiteTab = suiteTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (!event.invocationType().containsHttpRequestResponses()) {
            return List.of();
        }
        HttpRequest req = resolveRequest(event);
        if (req == null) {
            return List.of();
        }

        List<Component> items = new ArrayList<>();
        JMenuItem item = new JMenuItem("Create analytics service from request…");
        final HttpRequest captured = req;
        item.addActionListener(e -> SwingUtilities.invokeLater(() -> suiteTab.openNewServiceFromHttpRequest(captured)));
        items.add(item);
        return items;
    }

    private static HttpRequest resolveRequest(ContextMenuEvent event) {
        if (!event.selectedRequestResponses().isEmpty()) {
            HttpRequestResponse rr = event.selectedRequestResponses().get(0);
            if (rr != null && rr.request() != null) {
                return rr.request();
            }
        }
        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse rr = event.messageEditorRequestResponse().get().requestResponse();
            if (rr != null && rr.request() != null) {
                return rr.request();
            }
        }
        return null;
    }
}
