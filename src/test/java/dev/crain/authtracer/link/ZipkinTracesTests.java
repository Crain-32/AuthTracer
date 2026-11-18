package dev.crain.authtracer.link;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ZipkinTracesTests {

    @Test
    void theApiIsQueriedUnderTheBaseUrlsPathPerServiceForTheLookback() throws IOException {
        List<String> queries = new CopyOnWriteArrayList<>();
        HttpServer zipkin = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        zipkin.createContext("/zipkin/api/v2/traces", exchange -> {
            queries.add(exchange.getRequestURI().getRawQuery());
            byte[] body = """
                    [[{"traceId": "t1", "id": "a", "kind": "SERVER", "name": "get /orders",
                       "localEndpoint": {"serviceName": "order service"}, "tags": {"http.route": "/orders"}}]]
                    """.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        zipkin.start();
        try {
            URI base = URI.create("http://localhost:" + zipkin.getAddress().getPort() + "/zipkin");

            List<List<TraceSpan>> traces = ZipkinTraces.api(base, Duration.ofMinutes(5), 10)
                    .traces(List.of("order service", "billing"));

            // Zipkin's lookback is in milliseconds; a trace both queries return is read once.
            assertThat(queries).containsExactly("serviceName=order+service&lookback=300000&limit=10",
                    "serviceName=billing&lookback=300000&limit=10");
            assertThat(traces).singleElement().satisfies(trace -> assertThat(trace).singleElement()
                    .extracting(TraceSpan::service).isEqualTo("order service"));
        }
        finally {
            zipkin.stop(0);
        }
    }

    @Test
    void aZipkinThatFailsOrIsNotThereIsAnError() throws IOException {
        HttpServer failing = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        failing.createContext("/api/v2/traces", exchange -> {
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });
        failing.start();
        try {
            URI base = URI.create("http://localhost:" + failing.getAddress().getPort());
            assertThatIllegalStateException().isThrownBy(() -> ZipkinTraces.api(base, Duration.ofMinutes(5), 10)
                    .traces(List.of("orders"))).withMessageStartingWith("Zipkin returned 503 for " + base);
        }
        finally {
            failing.stop(0);
        }
        int closed;
        try (ServerSocket socket = new ServerSocket(0)) {
            closed = socket.getLocalPort();
        }
        URI nowhere = URI.create("http://localhost:" + closed);
        assertThatExceptionOfType(UncheckedIOException.class).isThrownBy(() -> ZipkinTraces.api(nowhere,
                Duration.ofMinutes(5), 10).traces(List.of("orders"))).withMessage("Can't reach Zipkin at " + nowhere);
    }

    @Test
    void aFileSavedFromTheApiIsReadAsItAnswers(@TempDir Path dir) throws IOException {
        // Two traces, one of them without spans.
        Path saved = Files.writeString(dir.resolve("traces.json"), """
                [[{"traceId": "t1", "id": "a", "parentId": null, "kind": "SERVER", "name": "get /orders",
                   "localEndpoint": {"serviceName": "orders"}}], []]
                """);

        assertThat(ZipkinTraces.file(saved).traces(List.of("orders"))).singleElement().satisfies(trace ->
                assertThat(trace).singleElement().satisfies(span -> {
                    assertThat(span.service()).isEqualTo("orders");
                    assertThat(span.parentId()).isNull();
                }));
        assertThatExceptionOfType(UncheckedIOException.class).isThrownBy(() -> ZipkinTraces.file(
                dir.resolve("missing.json")).traces(List.of("orders")));
    }

    @Test
    void aBlankTagIsNoTagAndTheNextNameIsTried() {
        TraceSpan span = new TraceSpan("t1", "a", null, "SERVER", "http get", "back", 0,
                Map.of("http.route", " ", "uri", "/items/{id}", "url.query", ""));

        assertThat(span.tag("http.route", "uri")).contains("/items/{id}");
        assertThat(span.tag("url.query")).isEmpty();
        assertThat(span.tag("http.url")).isEmpty();
    }

    @Test
    void spansKeepWhatTheLinkerReads() {
        List<List<TraceSpan>> traces = ZipkinTraces.parse("""
                [[{"traceId": "t1", "id": "b", "parentId": "a", "kind": "CLIENT", "name": "http get",
                   "timestamp": 1760000000000123, "localEndpoint": {"serviceName": "front"},
                   "tags": {"http.url": "http://back/items/7?view=full", "method": "GET"}},
                  {"traceId": "t1", "id": "c", "name": "authorize method",
                   "localEndpoint": {"serviceName": "back"}}]]
                """);

        assertThat(traces).singleElement().satisfies(trace -> {
            assertThat(trace.getFirst()).isEqualTo(new TraceSpan("t1", "b", "a", "CLIENT", "http get", "front",
                    1760000000000123L, Map.of("http.url", "http://back/items/7?view=full", "method", "GET")));
            TraceSpan local = trace.get(1);
            assertThat(local.parentId()).isNull();
            assertThat(local.kind()).isNull();
            assertThat(local.timestamp()).isZero();
            assertThat(local.tags()).isEmpty();
        });
    }

    @Test
    void aRelativePathStaysUnderTheBase() {
        assertThat(ZipkinTraces.under(URI.create("http://host/zipkin"), "api/v2/traces?x=1"))
                .hasToString("http://host/zipkin/api/v2/traces?x=1");
        assertThat(ZipkinTraces.under(URI.create("http://host:9411/"), "api/v2/traces"))
                .hasToString("http://host:9411/api/v2/traces");
        assertThat(ZipkinTraces.under(URI.create("http://host:9411"), "api/v2/traces"))
                .hasToString("http://host:9411/api/v2/traces");
    }
}
