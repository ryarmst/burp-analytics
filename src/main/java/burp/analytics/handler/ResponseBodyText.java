package burp.analytics.handler;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Safe UTF-8 preview of HTTP response bodies for regex scanning (size-capped). */
public final class ResponseBodyText {

    /** Default cap for manual history scans to limit memory and regex cost. */
    public static final int DEFAULT_MAX_BYTES = 1 << 20; // 1 MiB

    private ResponseBodyText() {}

    public static String utf8Preview(HttpResponse response, int maxBytes) {
        if (response == null || maxBytes <= 0) {
            return "";
        }
        var body = response.body();
        if (body == null || body.length() == 0) {
            return "";
        }
        byte[] raw = body.getBytes();
        if (raw.length > maxBytes) {
            raw = Arrays.copyOf(raw, maxBytes);
        }
        return new String(raw, StandardCharsets.UTF_8);
    }
}
