package burp.analytics.tools;

import burp.analytics.data.JsonServiceRepository;
import burp.analytics.data.ServiceDefinition;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class RuleEditorServer {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    private final Path servicesDirectory;
    private final JsonServiceRepository repository = new JsonServiceRepository();

    private RuleEditorServer(Path servicesDirectory) {
        this.servicesDirectory = servicesDirectory;
    }

    public static void main(String[] args) throws IOException {
        Path servicesDirectory = Path.of(args.length > 0 ? args[0] : "analytics").toAbsolutePath().normalize();
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 8765;
        RuleEditorServer app = new RuleEditorServer(servicesDirectory);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", app::handle);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("Analytics rule editor: http://127.0.0.1:" + port);
        System.out.println("Services directory: " + servicesDirectory);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if ("/".equals(path)) {
                write(exchange, 200, "text/html; charset=utf-8", html());
                return;
            }
            if ("/api/services".equals(path) && "GET".equals(exchange.getRequestMethod())) {
                JsonServiceRepository.LoadResult result = repository.loadAllWithReport(servicesDirectory);
                JsonObject body = new JsonObject();
                body.add("services", GSON.toJsonTree(result.definitions()));
                body.add("warnings", GSON.toJsonTree(result.warnings()));
                writeJson(exchange, 200, body);
                return;
            }
            if ("/api/services".equals(path) && "POST".equals(exchange.getRequestMethod())) {
                ServiceDefinition service = readService(exchange);
                List<String> errors = validate(service);
                if (!errors.isEmpty()) {
                    JsonObject body = new JsonObject();
                    body.add("errors", GSON.toJsonTree(errors));
                    writeJson(exchange, 400, body);
                    return;
                }
                repository.save(servicesDirectory, service);
                writeJson(exchange, 200, GSON.toJsonTree(service));
                return;
            }
            if (path.startsWith("/api/services/") && "DELETE".equals(exchange.getRequestMethod())) {
                String id = URLDecoder.decode(path.substring("/api/services/".length()), StandardCharsets.UTF_8);
                repository.delete(servicesDirectory, id);
                write(exchange, 204, "text/plain; charset=utf-8", "");
                return;
            }
            write(exchange, 404, "text/plain; charset=utf-8", "Not found");
        } catch (Exception e) {
            JsonObject body = new JsonObject();
            body.addProperty("error", e.getMessage());
            writeJson(exchange, 500, body);
        }
    }

    private static ServiceDefinition readService(HttpExchange exchange) throws IOException {
        try (Reader reader = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8)) {
            JsonObject object = JsonParser.parseReader(reader).getAsJsonObject();
            ServiceDefinition service = GSON.fromJson(object, ServiceDefinition.class);
            if (service.getId() == null || service.getId().isBlank()) {
                service.setId(UUID.randomUUID().toString());
            }
            service.normalize();
            return service;
        }
    }

    private static List<String> validate(ServiceDefinition service) {
        if (service == null) {
            return List.of("Service body is required.");
        }
        if (service.getName() == null || service.getName().isBlank()) {
            return List.of("Name is required.");
        }
        if (service.getPatterns().isEmpty()) {
            return List.of("At least one regex pattern is required.");
        }
        for (String pattern : service.getPatterns()) {
            try {
                Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                return List.of("Invalid regex: " + pattern + " (" + e.getDescription() + ")");
            }
        }
        return List.of();
    }

    private static void writeJson(HttpExchange exchange, int status, Object body) throws IOException {
        write(exchange, status, "application/json; charset=utf-8", GSON.toJson(body));
    }

    private static void write(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, status == 204 ? -1 : bytes.length);
        if (status != 204) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    private static String html() {
        return """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>Analytics Rule Editor</title>
                  <style>
                    body { margin: 0; font: 14px system-ui, sans-serif; color: #1f2937; background: #f8fafc; }
                    header { padding: 14px 18px; background: #111827; color: white; }
                    main { display: grid; grid-template-columns: 320px 1fr; gap: 16px; padding: 16px; }
                    button, input, textarea { font: inherit; }
                    button { padding: 7px 10px; border: 1px solid #cbd5e1; border-radius: 6px; background: white; cursor: pointer; }
                    button.primary { background: #2563eb; color: white; border-color: #2563eb; }
                    button.danger { color: #b91c1c; }
                    .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; box-shadow: 0 1px 2px #0000000d; }
                    .toolbar { display: flex; gap: 8px; margin-bottom: 10px; }
                    .list { display: flex; flex-direction: column; gap: 6px; max-height: calc(100vh - 150px); overflow: auto; }
                    .item { text-align: left; }
                    .item.active { background: #dbeafe; border-color: #93c5fd; }
                    label { display: block; margin: 10px 0 4px; font-weight: 600; }
                    input, textarea { box-sizing: border-box; width: 100%; border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px; background: white; }
                    textarea { min-height: 90px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
                    #patterns { min-height: 170px; }
                    .status { margin-top: 10px; white-space: pre-wrap; }
                    .warn { color: #92400e; }
                    .error { color: #b91c1c; }
                    .muted { color: #64748b; }
                  </style>
                </head>
                <body>
                  <header>
                    <strong>Analytics Rule Editor</strong>
                    <span class="muted">Edit service JSON files locally</span>
                  </header>
                  <main>
                    <section class="card">
                      <div class="toolbar">
                        <button onclick="newService()">New</button>
                        <button onclick="loadServices()">Reload</button>
                      </div>
                      <div id="warnings" class="status warn"></div>
                      <div id="serviceList" class="list"></div>
                    </section>
                    <section class="card">
                      <div class="toolbar">
                        <button class="primary" onclick="saveService()">Save</button>
                        <button class="danger" onclick="deleteService()">Delete</button>
                      </div>
                      <input id="id" type="hidden">
                      <label for="name">Name</label>
                      <input id="name" autocomplete="off">
                      <label for="description">Description</label>
                      <textarea id="description"></textarea>
                      <label for="methodology">Testing methodology</label>
                      <textarea id="methodology"></textarea>
                      <label for="patterns">Regex patterns, one per line</label>
                      <textarea id="patterns" spellcheck="false"></textarea>
                      <label><input id="tls" type="checkbox" style="width:auto"> TLS pass-through</label>
                      <div id="status" class="status"></div>
                    </section>
                  </main>
                  <script>
                    let services = [];
                    let selectedId = null;

                    function byId(id) { return document.getElementById(id); }
                    function setStatus(message, cls = "") {
                      const el = byId("status");
                      el.className = "status " + cls;
                      el.textContent = message;
                    }
                    function serviceFromForm() {
                      return {
                        schemaVersion: "1",
                        id: byId("id").value,
                        name: byId("name").value.trim(),
                        description: byId("description").value,
                        methodology: byId("methodology").value,
                        patterns: byId("patterns").value.split("\\n").map(s => s.trim()).filter(Boolean),
                        tlsPassThrough: byId("tls").checked,
                        tlsHostRegex: ""
                      };
                    }
                    function fillForm(service) {
                      selectedId = service?.id || "";
                      byId("id").value = service?.id || "";
                      byId("name").value = service?.name || "";
                      byId("description").value = service?.description || "";
                      byId("methodology").value = service?.methodology || "";
                      byId("patterns").value = (service?.patterns || []).join("\\n");
                      byId("tls").checked = Boolean(service?.tlsPassThrough);
                      renderList();
                    }
                    function newService() {
                      fillForm({ schemaVersion: "1", patterns: ["^analytics\\\\.example\\\\.com$"] });
                      setStatus("New service draft. Save to create a JSON file.");
                    }
                    function renderList() {
                      const list = byId("serviceList");
                      list.textContent = "";
                      services.forEach(service => {
                        const button = document.createElement("button");
                        button.className = "item" + (service.id === selectedId ? " active" : "");
                        button.textContent = service.name || service.id;
                        button.onclick = () => fillForm(service);
                        list.appendChild(button);
                      });
                    }
                    async function loadServices() {
                      const res = await fetch("/api/services");
                      const body = await res.json();
                      services = body.services || [];
                      byId("warnings").textContent = (body.warnings || []).join("\\n");
                      renderList();
                      if (services.length && !selectedId) fillForm(services[0]);
                      setStatus("Loaded " + services.length + " service(s).");
                    }
                    async function saveService() {
                      const res = await fetch("/api/services", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(serviceFromForm())
                      });
                      const body = await res.json();
                      if (!res.ok) {
                        setStatus((body.errors || [body.error || "Save failed"]).join("\\n"), "error");
                        return;
                      }
                      selectedId = body.id;
                      setStatus("Saved " + body.name + ".");
                      await loadServices();
                      fillForm(services.find(s => s.id === selectedId) || body);
                    }
                    async function deleteService() {
                      const id = byId("id").value;
                      if (!id || !confirm("Delete this service JSON file?")) return;
                      await fetch("/api/services/" + encodeURIComponent(id), { method: "DELETE" });
                      selectedId = null;
                      fillForm({});
                      await loadServices();
                      setStatus("Deleted service.");
                    }
                    loadServices().catch(e => setStatus(e.message, "error"));
                  </script>
                </body>
                </html>
                """;
    }
}
