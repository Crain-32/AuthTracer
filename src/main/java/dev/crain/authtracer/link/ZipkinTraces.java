package dev.crain.authtracer.link;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Trace sources speaking Zipkin's v2 JSON: the Zipkin query API, or a file saved from it.
 */
@Supports(Feature.TRACE_OBSERVATIONS)
public final class ZipkinTraces {

    private static final Logger log = LoggerFactory.getLogger(ZipkinTraces.class);
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private ZipkinTraces() {
    }

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Queries {@code api/v2/traces} once per service, under the base URL's path (a Zipkin behind a proxy at
     * {@code http://host/zipkin}).
     */
    public static TraceSource api(URI baseUrl, Duration lookback, int limit) {
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        return services -> {
            Map<String, List<TraceSpan>> traces = new LinkedHashMap<>();
            for (String service : services) {
                URI uri = under(baseUrl, "api/v2/traces?serviceName=" + URLEncoder.encode(service,
                        StandardCharsets.UTF_8) + "&lookback=" + lookback.toMillis() + "&limit=" + limit);
                try {
                    HttpResponse<String> response = http.send(HttpRequest.newBuilder(uri).timeout(REQUEST_TIMEOUT)
                            .GET().build(), HttpResponse.BodyHandlers.ofString());
                    if (response.statusCode() != 200) {
                        throw new IllegalStateException("Zipkin returned " + response.statusCode() + " for " + uri);
                    }
                    List<List<TraceSpan>> read = parse(response.body());
                    for (List<TraceSpan> trace : read) {
                        traces.putIfAbsent(trace.getFirst().traceId(), trace);
                    }
                    if (read.size() >= limit) {
                        log.warn("Zipkin returned {}'s limit of {} traces: older ones in the lookback aren't read",
                                service, limit);
                    }
                    else if (read.isEmpty()) {
                        log.warn("Zipkin has no traces of {} in the last {}: is the service named so in its traces?",
                                service, lookback);
                    }
                }
                catch (IOException ex) {
                    throw new UncheckedIOException("Can't reach Zipkin at " + baseUrl, ex);
                }
                catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(ex);
                }
            }
            log.info("Read {} traces for {} from Zipkin at {}", traces.size(), services, baseUrl);
            return new ArrayList<>(traces.values());
        };
    }

    /**
     * A path relative to a base URL's path: {@code http://host/zipkin} and {@code api/v2/traces} are
     * {@code http://host/zipkin/api/v2/traces}, where {@link URI#resolve} would drop {@code zipkin}.
     */
    static URI under(URI base, String relative) {
        String text = base.toString();
        return URI.create(text.endsWith("/") ? text : text + "/").resolve(relative);
    }

    public static TraceSource file(Path file) {
        return services -> {
            try {
                List<List<TraceSpan>> traces = parse(Files.readString(file));
                log.info("Read {} traces from {}", traces.size(), file);
                return traces;
            }
            catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        };
    }

    public static TraceSource of(List<List<TraceSpan>> traces) {
        return services -> traces;
    }

    static List<List<TraceSpan>> parse(String json) {
        List<List<TraceSpan>> traces = new ArrayList<>();
        for (JsonNode trace : MAPPER.readTree(json)) {
            List<TraceSpan> spans = new ArrayList<>();
            for (JsonNode span : trace) {
                Map<String, String> tags = new LinkedHashMap<>();
                JsonNode tagNode = span.path("tags");
                for (String name : tagNode.propertyNames()) {
                    tags.put(name, tagNode.get(name).asString());
                }
                spans.add(new TraceSpan(span.path("traceId").asString(), span.path("id").asString(),
                        text(span, "parentId"), text(span, "kind"), text(span, "name"),
                        span.path("localEndpoint").path("serviceName").asString(null),
                        span.path("timestamp").asLong(0), tags));
            }
            if (!spans.isEmpty()) {
                traces.add(spans);
            }
        }
        return traces;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asString();
    }
}
