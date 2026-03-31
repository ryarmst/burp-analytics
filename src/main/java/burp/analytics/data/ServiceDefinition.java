package burp.analytics.data;

import burp.analytics.util.PatternSanitizer;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Service definition (one JSON file per id). */
public final class ServiceDefinition {

    private String schemaVersion = "1";
    private String id;
    private String name = "";
    private String description = "";
    private String methodology = "";
    private List<String> patterns = new ArrayList<>();
    private boolean tlsPassThrough;
    private String tlsHostRegex = "";

    public static ServiceDefinition createNew(String name) {
        ServiceDefinition s = new ServiceDefinition();
        s.id = UUID.randomUUID().toString();
        s.name = name != null ? name : "New service";
        return s;
    }

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(String schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name : "";
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description != null ? description : "";
    }

    public String getMethodology() {
        return methodology;
    }

    public void setMethodology(String methodology) {
        this.methodology = methodology != null ? methodology : "";
    }

    public List<String> getPatterns() {
        if (patterns == null) {
            patterns = new ArrayList<>();
        }
        return patterns;
    }

    public void setPatterns(List<String> patterns) {
        this.patterns = patterns != null ? new ArrayList<>(patterns) : new ArrayList<>();
    }

    public boolean isTlsPassThrough() {
        return tlsPassThrough;
    }

    public void setTlsPassThrough(boolean tlsPassThrough) {
        this.tlsPassThrough = tlsPassThrough;
    }

    public String getTlsHostRegex() {
        return tlsHostRegex;
    }

    public void setTlsHostRegex(String tlsHostRegex) {
        this.tlsHostRegex = tlsHostRegex != null ? tlsHostRegex : "";
    }

    public void normalize() {
        if (patterns == null) {
            patterns = new ArrayList<>();
        }
        if (name == null) {
            name = "";
        }
        if (description == null) {
            description = "";
        }
        if (methodology == null) {
            methodology = "";
        }
        if (tlsHostRegex == null) {
            tlsHostRegex = "";
        }
        List<String> stripped = new ArrayList<>();
        for (String p : getPatterns()) {
            stripped.add(PatternSanitizer.stripSchemePrefix(p));
        }
        setPatterns(stripped);
    }

    public ServiceDefinition copy() {
        ServiceDefinition c = new ServiceDefinition();
        c.schemaVersion = this.schemaVersion;
        c.id = this.id;
        c.name = this.name;
        c.description = this.description;
        c.methodology = this.methodology;
        c.patterns = this.patterns != null ? new ArrayList<>(this.patterns) : new ArrayList<>();
        c.tlsPassThrough = this.tlsPassThrough;
        c.tlsHostRegex = this.tlsHostRegex;
        return c;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ServiceDefinition)) {
            return false;
        }
        ServiceDefinition that = (ServiceDefinition) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
