package burp.analytics.ui;

import burp.analytics.data.JsonServiceRepository;
import burp.analytics.data.ServiceDefinition;
import burp.analytics.matcher.AnalyticsMatcher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/** In-memory services; {@link #saveAll()} writes JSON files. */
public final class AnalyticsController {

    private final JsonServiceRepository repository = new JsonServiceRepository();
    private final AnalyticsMatcher matcher;
    private final CopyOnWriteArrayList<ServiceDefinition> definitions = new CopyOnWriteArrayList<>();
    private final Set<String> pendingDeletes = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean dirty = new AtomicBoolean(false);

    private volatile Path servicesDirectory;

    public AnalyticsController(AnalyticsMatcher matcher) {
        this.matcher = matcher;
    }

    public Path getServicesDirectory() {
        return servicesDirectory;
    }

    public void setServicesDirectory(Path dir) {
        this.servicesDirectory = dir;
    }

    public boolean isDirty() {
        return dirty.get();
    }

    public List<ServiceDefinition> getDefinitions() {
        return new ArrayList<>(definitions);
    }

    public void reloadFromDisk() throws IOException {
        pendingDeletes.clear();
        definitions.clear();
        if (servicesDirectory == null || !Files.isDirectory(servicesDirectory)) {
            matcher.updateDefinitions(List.of());
            dirty.set(false);
            return;
        }
        List<ServiceDefinition> loaded = repository.loadAll(servicesDirectory);
        definitions.addAll(loaded);
        matcher.updateDefinitions(getDefinitions());
        dirty.set(false);
    }

    public void upsert(ServiceDefinition def) {
        if (def == null) {
            return;
        }
        def.normalize();
        definitions.removeIf(d -> def.getId().equals(d.getId()));
        definitions.add(def);
        pendingDeletes.remove(def.getId());
        matcher.updateDefinitions(getDefinitions());
        dirty.set(true);
    }

    public void queueDelete(ServiceDefinition def) {
        if (def == null) {
            return;
        }
        definitions.removeIf(d -> def.getId().equals(d.getId()));
        pendingDeletes.add(def.getId());
        matcher.updateDefinitions(getDefinitions());
        dirty.set(true);
    }

    public void saveAll() throws IOException {
        if (servicesDirectory == null) {
            throw new IllegalStateException("Services directory not set");
        }
        Files.createDirectories(servicesDirectory);
        for (String id : pendingDeletes) {
            repository.delete(servicesDirectory, id);
        }
        pendingDeletes.clear();
        for (ServiceDefinition d : definitions) {
            repository.save(servicesDirectory, d);
        }
        dirty.set(false);
    }

    public void importFromJsonFiles(List<Path> files) throws IOException {
        for (Path p : files) {
            if (p == null || !Files.isRegularFile(p)) {
                continue;
            }
            ServiceDefinition def = repository.parseJsonFile(p);
            if (def != null && def.getId() != null && !def.getId().isBlank()) {
                upsert(def);
            }
        }
    }
}
