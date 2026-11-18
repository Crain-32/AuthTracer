package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The other ways RestTemplate, RestClient and WebClient requests are written.
 */
class ClientFormsFixtureTests {

    private final ApplicationGraph templates = FixtureScans.scan("templateforms");

    private final ApplicationGraph fluents = FixtureScans.scan("fluentforms");

    @Test
    void restOperationsCallsWithWholeUrlsInProperties() {
        Egress orders = egress(templates, "orders", "GET", "/api/orders");
        assertThat(orders.client()).isEqualTo("RestTemplate");
        assertThat(orders.baseUrl()).isEqualTo("https://orders.internal:8443");
        assertThat(orders.baseUrlExpression()).isEqualTo("${orders.url}");
        assertThat(orders.response()).isEqualTo(new Payload("fixtures.templateforms.Order", true, List.of()));
        assertThat(egress(templates, "place", "POST", "/api/orders").response().type())
                .isEqualTo("fixtures.templateforms.Receipt");
        // A property with no path is the service's root.
        Egress status = egress(templates, "shippingStatus", "GET", "/");
        assertThat(status.baseUrl()).isEqualTo("https://shipping.internal:8443");
        assertThat(status.baseUrlExpression()).isEqualTo("${shipping.url}");
    }

    @Test
    void requestEntitiesCarryTheMethodAndUrl() {
        Egress ship = egress(templates, "ship", "POST", "/shipments");
        assertThat(ship.baseUrl()).isEqualTo("https://shipping.internal:8443");
        assertThat(ship.baseUrlExpression()).isEqualTo("${shipping.url}");
        assertThat(ship.response().type()).isEqualTo("fixtures.templateforms.Receipt");
        assertThat(path(templates, "ingress:POST /orders/ship")).contains(ship.id());
        Egress cancel = egress(templates, "cancel", "PATCH", "/orders/{id}/cancel");
        assertThat(cancel.baseUrl()).isEqualTo("http://orders:8080");
        assertThat(cancel.response().type()).isEqualTo("java.lang.Void");
    }

    @Test
    void urlsBuiltInTheMethod() {
        assertThat(egress(templates, "status", "GET", "/orders/{p2}").baseUrl()).isEqualTo("http://status:8080");
        Egress docs = egress(templates, "docs", "GET", "/orders");
        assertThat(docs.baseUrl()).isEqualTo("http://docs:8080");
        assertThat(docs.query()).isEqualTo("view=full");
        // A host given as a template variable AuthTracer doesn't know the value of is no base URL.
        assertThat(egress(templates, "track", "GET", "{gateway}/tracking/{id}").baseUrl()).isNull();
        // String.format and a StringBuilder.
        assertThat(egress(templates, "formatted", "GET", "/orders/{p1}").baseUrl()).isEqualTo("http://orders:8080");
        assertThat(egress(templates, "built", "GET", "/orders/{p1}").baseUrl()).isEqualTo("http://orders:8080");
    }

    @Test
    void eachTemplateFieldHasItsOwnRootUri() {
        assertThat(egress(templates, "europe", "GET", "/regions/eu").baseUrl()).isEqualTo("http://eu.regions:8080");
        assertThat(egress(templates, "america", "GET", "/regions/us").baseUrl()).isEqualTo("http://us.regions:8080");
        // Built where it is used: the class's root URI.
        assertThat(egress(templates, "today", "GET", "/today").baseUrl()).isEqualTo("http://weather:8080");
        // A base URL from a @ConfigurationProperties record no file sets: where it comes from, and the path.
        Egress invoices = egress(templates, "invoices", "GET", "/invoices");
        assertThat(invoices.baseUrl()).isNull();
        assertThat(invoices.baseUrlExpression()).isEqualTo("${billing.url}");
    }

    @Test
    void urlsAuthTracerCantReadAreNotGuessed() {
        // Decision 0082: a URL from a parameter; a RequestEntity from a parameter. A whole URL may name its own host.
        assertThat(templates.nodes(Egress.class)).filteredOn(egress -> egress.uriTemplate().equals("?"))
                .extracting(egress -> egress.callSite().method(), Egress::httpMethod, Egress::baseUrl)
                .containsExactlyInAnyOrder(tuple("anywhere(java.lang.String)", "GET", null),
                        tuple("resend(org.springframework.http.RequestEntity)", "*", null));
        // A URL from a parameter, and uri lambdas that add a path from a parameter or a segment, under the base URL.
        assertThat(fluents.nodes(Egress.class)).filteredOn(egress -> egress.uriTemplate().equals("?"))
                .extracting(egress -> egress.callSite().method(), Egress::httpMethod, Egress::baseUrl)
                .containsExactlyInAnyOrder(tuple("anywhere(java.lang.String,java.lang.String)", "GET", null),
                        tuple("anywhere(java.lang.String,java.lang.String)", "GET", "http://orders:8080"));
    }

    @Test
    void theRequestBodyIsNotTheResponse() {
        Egress place = egress(fluents, "place", "POST", "/orders");
        assertThat(place.baseUrl()).isEqualTo("http://orders:8080");
        assertThat(place.response()).isEqualTo(new Payload("fixtures.fluentforms.Receipt", false, List.of()));
        assertThat(egress(fluents, "placeAll", "POST", "/orders/batch").response())
                .isEqualTo(new Payload("fixtures.fluentforms.Receipt", false, List.of()));
    }

    @Test
    void everyRequestInAMethodIsOneEgress() {
        assertThat(fluents.nodes(Egress.class)).filteredOn(egress -> egress.callSite().method().startsWith("refresh("))
                .extracting(Egress::httpMethod, Egress::uriTemplate, egress -> egress.response() == null ? null
                        : egress.response().type())
                .containsExactlyInAnyOrder(tuple("POST", "/orders/{id}/refresh", null),
                        tuple("GET", "/orders/{id}", "fixtures.fluentforms.Order"));
        assertThat(fluents.nodes(Egress.class)).filteredOn(egress -> egress.callSite().method().startsWith("touch("))
                .extracting(Egress::httpMethod, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("PATCH", "/orders/{id}/touch"), tuple("OPTIONS", "/"));
    }

    @Test
    void aRequestSpecAHelperBuilds() {
        Egress archived = egress(fluents, "request", "GET", "/archive/{id}");
        assertThat(archived.baseUrl()).isEqualTo("http://orders:8080");
        assertThat(path(fluents, "ingress:GET /archive/{id}")).contains(archived.id());
    }

    @Test
    void aQueryOnlyUriIsTheBaseUrlsRoot() {
        Egress page = egress(fluents, "page", "GET", "/");
        assertThat(page.baseUrl()).isEqualTo("http://orders:8080");
        assertThat(page.response()).isEqualTo(new Payload("fixtures.fluentforms.Order", true, List.of()));
    }

    @Test
    void clientsBuiltInlineOrPicked() {
        assertThat(egress(fluents, "health", "GET", "/health").baseUrl()).isEqualTo("http://health:8080");
        assertThat(egress(fluents, "regional", "GET", "/orders/{id}").baseUrl()).isNull();
    }

    @Test
    void webClientUrlsWithAHostFromAProperty() {
        Egress report = egress(fluents, "report", "GET", "/reports/{p2}");
        assertThat(report.client()).isEqualTo("WebClient");
        assertThat(report.baseUrl()).isEqualTo("http://reports.internal:8080");
        assertThat(egress(fluents, "summary", "GET", "/reports/summary").baseUrl()).isNull();
        Egress stream = egress(fluents, "stream", "GET", "/reports/stream");
        assertThat(stream.baseUrl()).isEqualTo("http://reports:8080");
        assertThat(stream.response()).isEqualTo(new Payload("java.lang.String", true, List.of()));
    }

    @Test
    void httpInterfacesDeclaredInOtherWays() {
        ApplicationGraph interfaces = FixtureScans.scan("httpinterfaceforms");
        String group = "${spring.http.serviceclient.default.base-url}";
        // A method given as an attribute, or not at all; a type-level url; no path; a type URL ending in a slash.
        assertThat(interfaces.nodes(Egress.class)).filteredOn(egress -> group.equals(egress.baseUrlExpression()))
                .extracting(Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl).containsExactlyInAnyOrder(
                        tuple("PATCH", "/catalog/items/{id}", "http://catalog:8080"),
                        tuple("*", "/catalog/items", "http://catalog:8080"),
                        tuple("GET", "/catalog", "http://catalog:8080"),
                        tuple("GET", "/api/users", "http://catalog:8080"));
    }

    @Test
    void httpInterfacesWiredInOtherWays() {
        ApplicationGraph interfaces = FixtureScans.scan("httpinterfaceforms");
        // On a WebClient, on RestTemplates with a root URI or a DefaultUriBuilderFactory, on a client with no base
        // URL; and an interface imported nowhere.
        assertThat(interfaces.nodes(Egress.class)).filteredOn(egress -> egress.baseUrlExpression() == null)
                .extracting(Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl).containsExactlyInAnyOrder(
                        tuple("GET", "/prices/{sku}", "http://prices:8080"),
                        tuple("GET", "/stock/{sku}", "http://stock:8080"),
                        tuple("GET", "/reviews", "http://reviews:8080"),
                        tuple("GET", "/", "http://reviews:8080"),
                        tuple("GET", "/legacy", null),
                        tuple("POST", "/audit", null));
    }

    private static Egress egress(ApplicationGraph graph, String method, String httpMethod, String uriTemplate) {
        List<Egress> found = graph.nodes(Egress.class).stream()
                .filter(egress -> egress.callSite().method().startsWith(method + "(")
                        && egress.httpMethod().equals(httpMethod) && egress.uriTemplate().equals(uriTemplate))
                .toList();
        assertThat(found).as(method + " " + httpMethod + " " + uriTemplate + " in " + graph.nodes(Egress.class))
                .hasSize(1);
        return found.getFirst();
    }
}
