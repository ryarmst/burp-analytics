package burp.analytics.matcher;

import burp.analytics.MatchStrings;
import burp.analytics.data.ServiceDefinition;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Compiled regex patterns per service (thread-safe snapshot). */
public final class AnalyticsMatcher {

    private final AtomicReference<Snapshot> ref = new AtomicReference<>(new Snapshot(List.of()));

    public void updateDefinitions(List<ServiceDefinition> definitions) {
        ref.set(Snapshot.compile(definitions != null ? definitions : List.of()));
    }

    public Optional<MatchResult> match(String matchTarget) {
        if (matchTarget == null) {
            return Optional.empty();
        }
        return ref.get().match(matchTarget);
    }

    public Optional<MatchResult> matchHttpRequest(HttpRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        for (String t : MatchStrings.matchTargetsForPattern(request)) {
            Optional<MatchResult> m = match(t);
            if (m.isPresent()) {
                return m;
            }
        }
        return Optional.empty();
    }

    private static final class Snapshot {
        private final List<Entry> entries;

        private Snapshot(List<Entry> entries) {
            this.entries = entries;
        }

        static Snapshot compile(List<ServiceDefinition> defs) {
            List<Entry> list = new ArrayList<>();
            for (ServiceDefinition def : defs) {
                if (def.getPatterns() == null) {
                    continue;
                }
                List<Pattern> pats = new ArrayList<>();
                List<String> originals = new ArrayList<>();
                for (String raw : def.getPatterns()) {
                    if (raw == null || raw.isBlank()) {
                        continue;
                    }
                    try {
                        pats.add(Pattern.compile(raw));
                        originals.add(raw);
                    } catch (PatternSyntaxException ignored) {
                    }
                }
                if (!pats.isEmpty()) {
                    list.add(new Entry(def, pats, originals));
                }
            }
            return new Snapshot(list);
        }

        Optional<MatchResult> match(String target) {
            for (Entry e : entries) {
                for (int i = 0; i < e.patterns.size(); i++) {
                    if (e.patterns.get(i).matcher(target).find()) {
                        return Optional.of(new MatchResult(e.service, e.originals.get(i)));
                    }
                }
            }
            return Optional.empty();
        }
    }

    private static final class Entry {
        final ServiceDefinition service;
        final List<Pattern> patterns;
        final List<String> originals;

        Entry(ServiceDefinition service, List<Pattern> patterns, List<String> originals) {
            this.service = service;
            this.patterns = patterns;
            this.originals = originals;
        }
    }
}
