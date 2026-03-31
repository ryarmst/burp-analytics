package burp.analytics.data;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

/** Load/save one JSON file per service; atomic save via temp file then move. */
public final class JsonServiceRepository {

    private static final String SUFFIX = ".json";

    private final Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public List<ServiceDefinition> loadAll(Path directory) throws IOException {
        List<ServiceDefinition> out = new ArrayList<>();
        if (directory == null || !Files.isDirectory(directory)) {
            return out;
        }
        try (Stream<Path> stream = Files.list(directory)) {
            stream
                    .filter(JsonServiceRepository::isServiceJsonFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .forEach(
                            path -> {
                                try {
                                    String json = Files.readString(path, StandardCharsets.UTF_8);
                                    ServiceDefinition def = gson.fromJson(json, ServiceDefinition.class);
                                    if (def != null && def.getId() != null && !def.getId().isBlank()) {
                                        def.normalize();
                                        out.add(def);
                                    }
                                } catch (JsonParseException | IOException ignored) {
                                }
                            });
        }
        return out;
    }

    private static boolean isServiceJsonFile(Path p) {
        if (!Files.isRegularFile(p)) {
            return false;
        }
        String fn = p.getFileName().toString();
        if (!fn.toLowerCase(Locale.ROOT).endsWith(SUFFIX)) {
            return false;
        }
        if (fn.startsWith(".")) {
            return false;
        }
        if (fn.startsWith("analytics-svc-")) {
            return false;
        }
        return true;
    }

    public ServiceDefinition parseJsonFile(Path file) throws IOException {
        if (file == null || !Files.isRegularFile(file)) {
            return null;
        }
        String json = Files.readString(file, StandardCharsets.UTF_8);
        ServiceDefinition def = gson.fromJson(json, ServiceDefinition.class);
        if (def != null) {
            def.normalize();
        }
        return def;
    }

    public void save(Path directory, ServiceDefinition def) throws IOException {
        if (directory == null || def == null || def.getId() == null || def.getId().isBlank()) {
            throw new IllegalArgumentException("Invalid directory or definition");
        }
        Files.createDirectories(directory);
        String fileName = sanitizeFileName(def.getId()) + SUFFIX;
        Path target = directory.resolve(fileName);
        Path temp = Files.createTempFile("analytics-svc-", SUFFIX);
        try {
            String json = gson.toJson(def);
            Files.writeString(temp, json, StandardCharsets.UTF_8);
            try {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.copy(temp, target, REPLACE_EXISTING);
                Files.deleteIfExists(temp);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    public void delete(Path directory, String id) throws IOException {
        if (directory == null || id == null || id.isBlank()) {
            return;
        }
        Path file = directory.resolve(sanitizeFileName(id) + SUFFIX);
        Files.deleteIfExists(file);
    }

    private static String sanitizeFileName(String id) {
        String s = id.replaceAll("[^a-zA-Z0-9._-]", "_");
        if (s.isEmpty()) {
            return "service";
        }
        return s.length() > 120 ? s.substring(0, 120) : s;
    }

    public static List<Path> listJsonFiles(Path dir) throws IOException {
        List<Path> paths = new ArrayList<>();
        if (dir == null || !Files.isDirectory(dir)) {
            return paths;
        }
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.json")) {
            for (Path p : ds) {
                if (isServiceJsonFile(p)) {
                    paths.add(p);
                }
            }
        }
        paths.sort(Comparator.comparing(p -> p.getFileName().toString()));
        return paths;
    }
}
