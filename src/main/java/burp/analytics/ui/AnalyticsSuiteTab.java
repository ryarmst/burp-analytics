package burp.analytics.ui;

import burp.analytics.data.ServiceDefinition;
import burp.analytics.session.SessionMatch;
import burp.analytics.session.SessionMatchStore;
import burp.analytics.export.FoxyProxyConfigExporter;
import burp.analytics.tls.TlsPatternHostRules;
import burp.analytics.tls.TlsProjectOptionsHelper;
import burp.analytics.util.RegexEscape;
import burp.analytics.util.RegexSuggest;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.Preferences;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class AnalyticsSuiteTab extends JPanel {

    private static final String PREF_DIR = "analytics.servicesDirectory";

    private static final String PROXY_TLS_BUCKET_NAME = "Proxy matches (TLS)";

    private final MontoyaApi api;
    private final Preferences preferences;
    private final AnalyticsController controller;
    private final SessionMatchStore sessionMatches;

    private final JTextField dirField = new JTextField(48);
    private final JButton saveButton = new JButton("Save");
    private final ServiceTableModel serviceModel = new ServiceTableModel();
    private final SessionTableModel sessionModel = new SessionTableModel();
    private final JTable serviceTable = new JTable(serviceModel);
    private final JTable sessionTable = new JTable(sessionModel);

    public AnalyticsSuiteTab(
            MontoyaApi api,
            Preferences preferences,
            AnalyticsController controller,
            SessionMatchStore sessionMatches) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.preferences = preferences;
        this.controller = controller;
        this.sessionMatches = sessionMatches;

        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout(4, 4));
        top.add(new JLabel("Services directory (JSON files):"), BorderLayout.NORTH);
        JPanel dirRow = new JPanel(new BorderLayout(4, 0));
        dirRow.add(dirField, BorderLayout.CENTER);
        JPanel dirBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JButton browse = new JButton("Browse…");
        browse.addActionListener(e -> browseDirectory());
        JButton load = new JButton("Load / reload");
        load.addActionListener(e -> loadDirectory());
        saveButton.setToolTipText("Write pending changes to JSON files in the services directory");
        saveButton.addActionListener(e -> saveAllToDisk());
        dirBtns.add(browse);
        dirBtns.add(load);
        dirBtns.add(saveButton);
        JButton foxyExport = new JButton("FoxyProxy JSON");
        foxyExport.setToolTipText(
                "Export a JSON array: TLS mirror excludes (full URL regex) plus a catch-all include wildcard for FoxyProxy");
        foxyExport.addActionListener(e -> exportFoxyProxyConfig());
        dirBtns.add(foxyExport);
        dirRow.add(dirBtns, BorderLayout.EAST);
        top.add(dirRow, BorderLayout.CENTER);

        JPanel svcPanel = new JPanel(new BorderLayout());
        svcPanel.setBorder(BorderFactory.createTitledBorder("Service definitions"));
        serviceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        serviceTable.setRowHeight(22);
        serviceTable.setFillsViewportHeight(true);
        serviceTable.setDefaultRenderer(Object.class, new TooltipRenderer());
        svcPanel.add(new JScrollPane(serviceTable), BorderLayout.CENTER);
        JPanel svcBtns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton add = new JButton("Add");
        add.addActionListener(e -> addService());
        JButton edit = new JButton("Edit");
        edit.addActionListener(e -> editService());
        JButton del = new JButton("Delete");
        del.addActionListener(e -> deleteService());
        JButton toggleTls = new JButton("Toggle TLS pass-through");
        toggleTls.setToolTipText(
                "Enable/disable TLS pass-through for the selected service; host rules are derived from URL patterns and merged into Burp project options");
        toggleTls.addActionListener(e -> toggleTlsPassThroughForSelected());
        JButton imp = new JButton("Import JSON…");
        imp.addActionListener(e -> importJson());
        JButton exp = new JButton("Export all to folder…");
        exp.addActionListener(e -> exportAll());
        svcBtns.add(add);
        svcBtns.add(edit);
        svcBtns.add(del);
        svcBtns.add(toggleTls);
        svcBtns.add(imp);
        svcBtns.add(exp);
        svcPanel.add(svcBtns, BorderLayout.SOUTH);

        JPanel sessPanel = new JPanel(new BorderLayout());
        sessPanel.setBorder(BorderFactory.createTitledBorder("Proxy matches (this session, one row per FQDN)"));
        sessionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sessionTable.setRowHeight(22);
        sessionTable.setFillsViewportHeight(true);
        sessionTable.setDefaultRenderer(Object.class, new TooltipRenderer());
        sessPanel.add(new JScrollPane(sessionTable), BorderLayout.CENTER);
        JPanel sessBtns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clear = new JButton("Clear session list");
        clear.addActionListener(
                e -> {
                    sessionMatches.clear();
                    refreshSessionTable();
                });
        JButton repeater = new JButton("Send to Repeater");
        repeater.setToolTipText("Send the selected request to Repeater for manual tuning, then edit the service to adjust patterns");
        repeater.addActionListener(e -> sendSelectedToRepeater());
        JButton cfg = new JButton("Configure service…");
        cfg.setToolTipText("Edit the service definition that matched this row");
        cfg.addActionListener(e -> configureServiceFromSessionRow());
        JButton addTlsSession = new JButton("Add session hosts to TLS…");
        addTlsSession.setToolTipText(
                "For each unique FQDN in this list, add a host-only pattern to TLS pass-through (skips hosts already covered)");
        addTlsSession.addActionListener(e -> addSessionHostsToTlsPassThrough());
        sessBtns.add(clear);
        sessBtns.add(repeater);
        sessBtns.add(cfg);
        sessBtns.add(addTlsSession);
        sessPanel.add(sessBtns, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, svcPanel, sessPanel);
        split.setResizeWeight(0.5);

        add(top, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        updateSaveButtonState();

        String saved = preferences.getString(PREF_DIR);
        if (saved != null && !saved.isBlank()) {
            dirField.setText(saved);
            controller.setServicesDirectory(Path.of(saved));
            try {
                controller.reloadFromDisk();
                serviceModel.setRows(controller.getDefinitions());
            } catch (Exception ex) {
                api.logging().logToError("Analytics: could not load saved directory: " + ex.getMessage());
            }
        }
        updateSaveButtonState();
    }

    public void refreshAfterSessionMatch() {
        refreshSessionTable();
    }

    public void openNewServiceFromHttpRequest(HttpRequest req) {
        if (req == null) {
            return;
        }
        ensureDir();
        String host = req.httpService().host();
        ServiceDefinition draft = ServiceDefinition.createNew(host.isEmpty() ? "New service" : host);
        draft.normalize();
        draft.getPatterns().clear();
        draft.getPatterns().add(RegexSuggest.literalMatchForRequest(req));
        ServiceDefinition out =
                ServiceEditDialog.show(SwingUtilities.getWindowAncestor(this), "New analytics service", draft);
        if (out != null) {
            controller.upsert(out);
            serviceModel.setRows(controller.getDefinitions());
            updateSaveButtonState();
        }
    }

    private void updateSaveButtonState() {
        saveButton.setEnabled(controller.isDirty());
    }

    private void saveAllToDisk() {
        if (controller.getServicesDirectory() == null) {
            JOptionPane.showMessageDialog(this, "Set a services directory first.", "Save", JOptionPane.WARNING_MESSAGE);
            return;
        }
        try {
            controller.saveAll();
            serviceModel.setRows(controller.getDefinitions());
            updateSaveButtonState();
            api.logging().logToOutput("Analytics: saved " + controller.getDefinitions().size() + " service(s).");
        } catch (Exception ex) {
            api.logging().logToError("Analytics: save failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void browseDirectory() {
        JFileChooser ch = new JFileChooser();
        ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = ch.getSelectedFile();
            if (f != null) {
                dirField.setText(f.getAbsolutePath());
            }
        }
    }

    private void loadDirectory() {
        if (controller.isDirty()) {
            int r =
                    JOptionPane.showConfirmDialog(
                            this,
                            "Discard unsaved changes and reload from disk?",
                            "Reload",
                            JOptionPane.OK_CANCEL_OPTION);
            if (r != JOptionPane.OK_OPTION) {
                return;
            }
        }
        String path = dirField.getText().trim();
        if (path.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Choose a directory.", "Directory", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Path p = Path.of(path);
        controller.setServicesDirectory(p);
        preferences.setString(PREF_DIR, path);
        try {
            controller.reloadFromDisk();
            serviceModel.setRows(controller.getDefinitions());
            updateSaveButtonState();
            api.logging().logToOutput("Analytics: loaded " + controller.getDefinitions().size() + " service(s).");
        } catch (Exception ex) {
            api.logging().logToError("Analytics: load failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Load failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void addService() {
        ensureDir();
        ServiceDefinition draft = ServiceDefinition.createNew("New service");
        draft.normalize();
        ServiceDefinition saved =
                ServiceEditDialog.show(SwingUtilities.getWindowAncestor(this), "Add service", draft);
        if (saved != null) {
            controller.upsert(saved);
            serviceModel.setRows(controller.getDefinitions());
            updateSaveButtonState();
        }
    }

    private void editService() {
        int row = serviceTable.getSelectedRow();
        if (row < 0) {
            return;
        }
        ServiceDefinition cur = serviceModel.getRow(row);
        ServiceDefinition updated =
                ServiceEditDialog.show(SwingUtilities.getWindowAncestor(this), "Edit service", cur.copy());
        if (updated != null) {
            controller.upsert(updated);
            serviceModel.setRows(controller.getDefinitions());
            updateSaveButtonState();
        }
    }

    private void deleteService() {
        int row = serviceTable.getSelectedRow();
        if (row < 0) {
            return;
        }
        ServiceDefinition cur = serviceModel.getRow(row);
        int ok =
                JOptionPane.showConfirmDialog(
                        this, "Remove " + cur.getName() + " from the list? (Save writes the deletion to disk.)", "Confirm", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        controller.queueDelete(cur);
        serviceModel.setRows(controller.getDefinitions());
        updateSaveButtonState();
    }

    private void toggleTlsPassThroughForSelected() {
        int row = serviceTable.getSelectedRow();
        if (row < 0) {
            api.logging().logToOutput("Analytics: select a service row to toggle TLS pass-through.");
            return;
        }
        ServiceDefinition s = serviceModel.getRow(row).copy();
        s.setTlsPassThrough(!s.isTlsPassThrough());
        controller.upsert(s);
        serviceModel.setRows(controller.getDefinitions());
        updateSaveButtonState();
        TlsProjectOptionsHelper.mergeTlsRulesIntoBurp(api, controller.getDefinitions());
    }

    private void addSessionHostsToTlsPassThrough() {
        List<SessionMatch> rows = sessionMatches.snapshot();
        if (rows.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this, "No proxy matches in this session.", "TLS pass-through", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Set<String> hostRulesFromTls = new LinkedHashSet<>();
        for (ServiceDefinition d : controller.getDefinitions()) {
            if (d != null && d.isTlsPassThrough()) {
                hostRulesFromTls.addAll(TlsPatternHostRules.hostRulesFromPatterns(d.getPatterns()));
            }
        }
        ServiceDefinition bucket = findOrCreateProxyTlsBucket();
        Set<String> patternLines = new LinkedHashSet<>(bucket.getPatterns());
        int added = 0;
        int skippedDuplicates = 0;
        Set<String> seenFq = new LinkedHashSet<>();
        for (SessionMatch m : rows) {
            String fq = m.getFqdn();
            if (fq == null || fq.isBlank()) {
                continue;
            }
            if (!seenFq.add(fq)) {
                continue;
            }
            String pat = "^" + RegexEscape.escape(fq) + "$";
            List<String> derived = TlsPatternHostRules.hostRulesFromPatterns(List.of(pat));
            String hostRule = derived.isEmpty() ? pat : derived.get(0);
            if (hostRulesFromTls.contains(hostRule)) {
                skippedDuplicates++;
                continue;
            }
            if (patternLines.contains(pat)) {
                skippedDuplicates++;
                continue;
            }
            bucket.getPatterns().add(pat);
            patternLines.add(pat);
            hostRulesFromTls.add(hostRule);
            bucket.setTlsPassThrough(true);
            added++;
        }
        if (added == 0) {
            JOptionPane.showMessageDialog(
                    this,
                    "No new hosts to add. Every session FQDN is already represented in a TLS pass-through host rule.",
                    "TLS pass-through",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        controller.upsert(bucket);
        serviceModel.setRows(controller.getDefinitions());
        updateSaveButtonState();
        TlsProjectOptionsHelper.mergeTlsRulesIntoBurp(api, controller.getDefinitions());
        api.logging()
                .logToOutput(
                        "Analytics: added " + added + " host pattern(s) from proxy matches to \"" + PROXY_TLS_BUCKET_NAME + "\".");
        JOptionPane.showMessageDialog(
                this,
                "Added "
                        + added
                        + " host pattern(s) to \""
                        + PROXY_TLS_BUCKET_NAME
                        + "\" with TLS pass-through enabled."
                        + (skippedDuplicates > 0 ? (" Skipped " + skippedDuplicates + " already covered or duplicate.") : "")
                        + "\nSave to persist the JSON file.",
                "TLS pass-through",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private ServiceDefinition findOrCreateProxyTlsBucket() {
        for (ServiceDefinition d : controller.getDefinitions()) {
            if (d != null && PROXY_TLS_BUCKET_NAME.equals(d.getName())) {
                return d.copy();
            }
        }
        ServiceDefinition b = ServiceDefinition.createNew(PROXY_TLS_BUCKET_NAME);
        b.setDescription("Hosts added from the proxy session match list. You can edit, rename, or merge this service.");
        b.setTlsPassThrough(true);
        return b;
    }

    private void importJson() {
        ensureDir();
        JFileChooser ch = new JFileChooser();
        ch.setMultiSelectionEnabled(true);
        if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File[] files = ch.getSelectedFiles();
            List<Path> paths = new ArrayList<>();
            for (File f : files) {
                if (f != null && f.getName().toLowerCase().endsWith(".json")) {
                    paths.add(f.toPath());
                }
            }
            try {
                controller.importFromJsonFiles(paths);
                serviceModel.setRows(controller.getDefinitions());
                updateSaveButtonState();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportAll() {
        JFileChooser ch = new JFileChooser();
        ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (ch.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File dest = ch.getSelectedFile();
        if (dest == null) {
            return;
        }
        try {
            Path d = dest.toPath();
            java.nio.file.Files.createDirectories(d);
            for (ServiceDefinition s : controller.getDefinitions()) {
                new burp.analytics.data.JsonServiceRepository().save(d, s);
            }
            JOptionPane.showMessageDialog(
                    this,
                    "Exported " + controller.getDefinitions().size() + " file(s).",
                    "OK",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportFoxyProxyConfig() {
        JFileChooser ch = new JFileChooser();
        ch.setSelectedFile(new File("foxyproxy-excludes.json"));
        if (ch.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File dest = ch.getSelectedFile();
        if (dest == null) {
            return;
        }
        try {
            String json = FoxyProxyConfigExporter.buildExcludesJson(controller.getDefinitions());
            Files.writeString(dest.toPath(), json, StandardCharsets.UTF_8);
            int n = FoxyProxyConfigExporter.tlsExcludeRuleCount(controller.getDefinitions());
            api.logging()
                    .logToOutput(
                            "Analytics: wrote FoxyProxy pattern list with "
                                    + n
                                    + " TLS mirror exclude(s) and a catch-all include wildcard.");
            String msg =
                    n == 0
                            ? "Saved JSON array. No TLS mirror excludes — only the \"Everything Else\" include wildcard row. Toggle TLS on services and Save, or edit patterns to add excludes."
                            : "Saved JSON array: TLS mirror excludes plus a final \"Everything Else\" include wildcard (*).\n"
                                    + "Add them in FoxyProxy (backup first). Exclude patterns are full-URL regex aligned with Burp TLS pass-through host rules.";
            JOptionPane.showMessageDialog(this, msg, "OK", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Analytics: FoxyProxy export failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void ensureDir() {
        if (controller.getServicesDirectory() == null) {
            loadDirectory();
        }
    }

    private void refreshSessionTable() {
        sessionModel.setRows(sessionMatches.snapshot());
    }

    private void sendSelectedToRepeater() {
        int row = sessionTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Select a proxy match row.", "Repeater", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        SessionMatch m = sessionModel.getRow(row);
        if (m.getEvidence() == null) {
            return;
        }
        try {
            api.repeater().sendToRepeater(m.getEvidence().request(), "Analytics: " + m.getServiceName());
            api.logging().logToOutput("Analytics: sent request to Repeater for " + m.getServiceName());
        } catch (Exception ex) {
            api.logging().logToError("Analytics: send to Repeater failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Could not send to Repeater: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void configureServiceFromSessionRow() {
        int row = sessionTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Select a proxy match row.", "Configure", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        SessionMatch m = sessionModel.getRow(row);
        ServiceDefinition svc = findById(m.getServiceId());
        if (svc == null) {
            JOptionPane.showMessageDialog(this, "Service definition not found (reload directory?).", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        ServiceDefinition updated =
                ServiceEditDialog.show(SwingUtilities.getWindowAncestor(this), "Configure service: " + svc.getName(), svc.copy());
        if (updated != null) {
            controller.upsert(updated);
            serviceModel.setRows(controller.getDefinitions());
            updateSaveButtonState();
        }
    }

    private ServiceDefinition findById(String id) {
        for (ServiceDefinition d : controller.getDefinitions()) {
            if (d.getId().equals(id)) {
                return d;
            }
        }
        return null;
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    private static final class TooltipRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c =
                    super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (c instanceof JLabel && value != null) {
                String t = value.toString();
                ((JLabel) c).setToolTipText(t.length() > 80 ? t : null);
            }
            return c;
        }
    }

    private static final class ServiceTableModel extends AbstractTableModel {
        private final String[] cols = {"Name", "TLS"};
        private List<ServiceDefinition> rows = new ArrayList<>();

        void setRows(List<ServiceDefinition> r) {
            this.rows = new ArrayList<>(r);
            fireTableDataChanged();
        }

        ServiceDefinition getRow(int i) {
            return rows.get(i);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int column) {
            return cols[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ServiceDefinition s = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> s.getName();
                case 1 -> s.isTlsPassThrough();
                default -> "";
            };
        }
    }

    private static final class SessionTableModel extends AbstractTableModel {
        private final String[] cols = {"FQDN", "Time", "Service", "Pattern", "Match target"};
        private final DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());
        private List<SessionMatch> rows = new ArrayList<>();

        void setRows(List<SessionMatch> r) {
            this.rows = new ArrayList<>(r);
            fireTableDataChanged();
        }

        SessionMatch getRow(int i) {
            return rows.get(i);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int column) {
            return cols[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            SessionMatch m = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> m.getFqdn();
                case 1 -> fmt.format(m.getTime());
                case 2 -> m.getServiceName();
                case 3 -> truncate(m.getMatchedPattern(), 48);
                case 4 -> truncate(m.getMatchTarget(), 64);
                default -> "";
            };
        }
    }
}
