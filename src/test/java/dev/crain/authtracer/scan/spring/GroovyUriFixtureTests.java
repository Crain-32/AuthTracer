package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Dynamic Groovy client chains that pass closures: each is the functional interface Groovy coerces it to, so the
 * chain stays typed and the call is read; a closure it can't read is an Egress to ?.
 */
class GroovyUriFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("groovyuri");

    @Test
    void aUriClosureIsReadAsTheFunctionItIs() {
        assertThat(graph.nodes(Egress.class)).extracting(egress -> egress.callSite().method(), Egress::client,
                Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl, egress -> egress.response() == null ? null
                        : egress.response().type())
                .containsExactlyInAnyOrder(
                        // On the closure's own parameter, and on a typed one.
                        tuple("order(java.lang.Long)", "RestClient", "GET", "/orders/{id}", "http://orders:8080",
                                "java.lang.String"),
                        tuple("lines(java.lang.Long)", "RestClient", "GET", "/orders/lines", "http://orders:8080",
                                "java.lang.String"),
                        tuple("elsewhere(java.lang.String)", "RestClient", "GET", "?", "http://orders:8080",
                                "java.lang.String"),
                        // A headers closure after the uri keeps the chain typed to its response.
                        tuple("audit()", "RestClient", "POST", "/audit", "http://orders:8080", "java.lang.String"),
                        tuple("legacy()", "RestTemplate", "GET", "/stock", "http://legacy:8080", null));
        assertThat(path(graph, "ingress:GET /orders/{id}")).contains(
                "egress:fixtures.groovyuri.OrdersController#order(java.lang.Long) GET /orders/{id}");
    }

    @Test
    void aClosureThatAddsAPathFromElsewhereIsAnUnknownPath() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement().asString().contains(
                        "OrdersController#elsewhere(java.lang.String) sends GET to http://orders:8080 with a path"
                                + " AuthTracer can't read (UriBuilder.path(..) with a value that isn't a constant)");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH);
    }
}
