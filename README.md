# Analytics Database (Burp extension)

Define analytics and third-party services as JSON, match **Proxy** traffic with regex on **host[:port] + path + query** and get Site Map issues when new domains hit your rules.

## Build and load

- **JDK 17+**, then `./gradlew jar` → `build/libs/analytics-burp-extension.jar` (Gson bundled; Montoya comes from Burp).
- **CI:** [GitHub Actions](.github/workflows/build.yml) builds on push/PR and uploads the JAR as an artifact. **Releases:** either push a `v*` tag (JAR attached automatically) or create/publish a release in the GitHub UI (a workflow run attaches the JAR when the release is **published**).
- Install the JAR under **Extensions**, open the **Analytics DB** tab, and point **Services directory** at a folder of one JSON file per service (`analytics/` has samples).

## Patterns

- **Save** / **Load** sync that folder. **Import JSON** pulls files in.
- **Toggle TLS pass-through** (per service) merges derived host rules into Burp **TLS pass through** from your URL patterns.
- **Proxy matches** lists session FQDNs; **Add session hosts to TLS…** appends missing hosts to a **Proxy matches (TLS)** service and syncs Burp (skips duplicates).
- **FoxyProxy JSON** exports exclude rules for TLS-mirrored hosts (plus a catch-all include row); use your Burp listener in FoxyProxy separately.
- Right-click a request → **Create analytics service from request…** to pre-fill a host-only pattern.

## Issues

New FQDNs in the session list get an informational **Site Map** issue (metadata uses **Origin**, else **Referer**, else the request URL).

## TODO
Consider using data from:
- https://github.com/duckduckgo/tracker-radar
- https://github.com/ghostery/trackerdb
