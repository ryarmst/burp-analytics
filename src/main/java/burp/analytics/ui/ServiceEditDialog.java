package burp.analytics.ui;

import burp.analytics.data.ServiceDefinition;
import burp.analytics.util.PatternSanitizer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Window;
import java.util.ArrayList;
import java.util.List;

/** Add/edit service (scrollable form). */
final class ServiceEditDialog extends JDialog {

    private final JTextField nameField = new JTextField();
    private final JTextArea descArea = new JTextArea();
    private final JTextArea methodologyArea = new JTextArea();
    private final JTextArea patternsArea = new JTextArea();

    private ServiceDefinition result;

    private ServiceEditDialog(Window owner, String title, ServiceDefinition edit) {
        super(owner, title);
        setModal(true);
        setLayout(new BorderLayout(8, 8));

        ServiceDefinition safe = edit != null ? edit.copy() : ServiceDefinition.createNew("New service");
        safe.normalize();

        nameField.setText(safe.getName());
        descArea.setText(safe.getDescription());
        methodologyArea.setText(safe.getMethodology());
        patternsArea.setText(String.join("\n", safe.getPatterns()));

        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, nameField.getFont().getSize());
        patternsArea.setFont(mono);
        for (JTextArea a : new JTextArea[] {descArea, methodologyArea, patternsArea}) {
            a.setLineWrap(true);
            a.setWrapStyleWord(true);
            a.setTabSize(2);
        }

        JPanel form = new JPanel();
        form.setLayout(new javax.swing.BoxLayout(form, javax.swing.BoxLayout.Y_AXIS));
        form.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        form.add(sectionLabel("Name"));
        nameField.setMaximumSize(new Dimension(Integer.MAX_VALUE, nameField.getPreferredSize().height));
        form.add(nameField);
        form.add(Box.createVerticalStrut(8));

        form.add(sectionLabel("Description"));
        form.add(wrapScroll(descArea, 100));
        form.add(Box.createVerticalStrut(8));

        form.add(sectionLabel("Testing methodology"));
        form.add(wrapScroll(methodologyArea, 120));
        form.add(Box.createVerticalStrut(8));

        form.add(
                sectionLabel(
                        "Regex patterns (Host match)"));
        form.add(wrapScroll(patternsArea, 180));
        form.add(Box.createVerticalStrut(8));

        JLabel hint =
                new JLabel(
                        "Example: ^analytics\\.example\\.com$");
        hint.setAlignmentX(LEFT_ALIGNMENT);
        form.add(hint);

        JScrollPane scroll = new JScrollPane(form);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setPreferredSize(new Dimension(700, 520));
        add(scroll, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton ok = new JButton("OK");
        JButton cancel = new JButton("Cancel");
        ok.addActionListener(e -> onOk(safe));
        cancel.addActionListener(
                e -> {
                    result = null;
                    dispose();
                });
        buttons.add(ok);
        buttons.add(cancel);
        add(buttons, BorderLayout.SOUTH);

        pack();
        setMinimumSize(new Dimension(640, 480));
        setLocationRelativeTo(owner);
        SwingUtilities.invokeLater(
                () -> {
                    nameField.requestFocusInWindow();
                    nameField.selectAll();
                });
    }

    private static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    private static JScrollPane wrapScroll(JTextArea area, int minHeight) {
        area.setRows(4);
        area.setColumns(40);
        JScrollPane sp = new JScrollPane(area);
        sp.setAlignmentX(LEFT_ALIGNMENT);
        Dimension d = sp.getPreferredSize();
        sp.setMinimumSize(new Dimension(200, minHeight));
        sp.setPreferredSize(new Dimension(Math.max(d.width, 560), minHeight));
        sp.setMaximumSize(new Dimension(Integer.MAX_VALUE, minHeight + 80));
        return sp;
    }

    private void onOk(ServiceDefinition template) {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Name is required.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        List<String> patterns = new ArrayList<>();
        for (String line : patternsArea.getText().split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) {
                continue;
            }
            if (PatternSanitizer.containsScheme(t)) {
                JOptionPane.showMessageDialog(
                        this,
                        "Patterns must not include http:// or https://. Remove the scheme and try again.",
                        "Validation",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            patterns.add(PatternSanitizer.stripSchemePrefix(t));
        }
        if (patterns.isEmpty()) {
            JOptionPane.showMessageDialog(this, "At least one regex pattern is required.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        ServiceDefinition out = template.copy();
        out.setName(name);
        out.setDescription(descArea.getText());
        out.setMethodology(methodologyArea.getText());
        out.setPatterns(patterns);
        result = out;
        dispose();
    }

    static ServiceDefinition show(Window owner, String title, ServiceDefinition edit) {
        ServiceEditDialog d = new ServiceEditDialog(owner, title, edit);
        d.setVisible(true);
        return d.result;
    }
}
