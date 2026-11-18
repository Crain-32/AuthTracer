package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class ClientsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("clients");

    @Test
    void restTemplateConcatenatesAValueBaseUrl() {
        Egress product = egress("RestTemplate", "/catalog/products/{p2}");
        assertThat(product.httpMethod()).isEqualTo("GET");
        assertThat(product.baseUrlExpression()).isEqualTo("${catalog.base-url}");
        assertThat(product.response()).isEqualTo(new Payload("fixtures.clients.Product", false));
    }

    @Test
    void restTemplateSplitsAbsoluteUrlsAndReadsExchangeMethods() {
        Egress archive = egress("RestTemplate", "/archive/{id}");
        assertThat(archive.httpMethod()).isEqualTo("PUT");
        assertThat(archive.baseUrl()).isEqualTo("http://archive:9090");
        assertThat(egress("RestTemplate", "/cache/{id}").httpMethod()).isEqualTo("DELETE");
    }

    @Test
    void webClientIsAFluentClient() {
        Egress price = egress("WebClient", "/prices/{id}");
        assertThat(price.httpMethod()).isEqualTo("GET");
        assertThat(price.baseUrl()).isEqualTo("http://pricing:8081");
        assertThat(price.response()).isEqualTo(new Payload("fixtures.clients.Price", false));
        assertThat(egress("WebClient", "/prices/{id}/history").response())
                .isEqualTo(new Payload("fixtures.clients.Price", true));
        // client.get().header(..).retrieve(), without uri(..): the base URL itself.
        Egress current = egress("WebClient", "/");
        assertThat(current.httpMethod()).isEqualTo("GET");
        assertThat(current.baseUrl()).isEqualTo("http://pricing:8081");
        assertThat(current.response()).isEqualTo(new Payload("fixtures.clients.Price", false));
    }

    @Test
    void aClientFromABeanMethodHasThatMethodsBaseUrl() {
        assertThat(egress("RestClient", "/partners/{id}").baseUrl()).isEqualTo("http://partner:7070");
    }

    @Test
    void aBaseUrlsPathGoesBeforeTheRequestsPath() {
        assertThat(egress("RestClient", "/api/v1/orders/{id}").baseUrl()).isEqualTo("http://orders:8080");
    }

    @Test
    void eachClientHasTheBaseUrlItsFieldWasBuiltWith() {
        assertThat(egress("RestClient", "/users/{id}").baseUrl()).isEqualTo("http://users:8081");
        assertThat(egress("RestClient", "/purchases/{id}").baseUrl()).isEqualTo("http://purchases:8082");
    }

    @Test
    void httpInterfaceCallsAreEgress() {
        Egress stock = egress("HTTP interface", "/inventory/stock/{sku}");
        assertThat(stock.httpMethod()).isEqualTo("GET");
        assertThat(stock.baseUrlExpression()).isEqualTo("${spring.http.serviceclient.inventory.base-url}");
        assertThat(stock.response()).isEqualTo(new Payload("fixtures.clients.Stock", true));
        assertThat(egress("HTTP interface", "/inventory/reservations/{sku}").httpMethod()).isEqualTo("POST");
        assertThat(egress("HTTP interface", "/inventory/levels/{sku}").httpMethod()).isEqualTo("GET");
    }

    @Test
    void egressIsOnTheRequestPath() {
        List<String> path = FixtureScans.path(graph, "ingress:GET /products/{id}/stock");
        assertThat(path).anySatisfy(id -> assertThat(id).contains("POST /inventory/reservations/{sku}"))
                .anySatisfy(id -> assertThat(id).contains("GET /inventory/stock/{sku}"));
    }

    private Egress egress(String client, String uriTemplate) {
        List<Egress> found = graph.nodes(Egress.class).stream()
                .filter(egress -> egress.client().equals(client) && egress.uriTemplate().equals(uriTemplate))
                .toList();
        assertThat(found).as(client + " " + uriTemplate + " in " + graph.nodes(Egress.class)).hasSize(1);
        return found.getFirst();
    }

    @Test
    void theJdksHttpClient() {
        ApplicationGraph jdk = FixtureScans.scan("jdkclient");
        assertThat(jdk.nodes(Egress.class)).extracting(Egress::client, Egress::httpMethod, Egress::uriTemplate,
                Egress::baseUrl).containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("HttpClient", "GET", "/api/items", "http://localhost:8090"),
                        org.assertj.core.groups.Tuple.tuple("HttpClient", "POST", "/api/items", "http://localhost:8090"));
    }

    @Test
    void theJdksHttpClientsOtherForms() {
        ApplicationGraph jdk = FixtureScans.scan("jdkclientforms");
        // sendAsync with no method set (GET), method("PATCH", ..), and method(verb, ..): any method. A request to a
        // URL from a parameter, or a request from one (any method), goes to a URL AuthTracer can't read.
        assertThat(jdk.nodes(Egress.class)).extracting(egress -> egress.callSite().method(), Egress::httpMethod,
                Egress::uriTemplate, Egress::baseUrl, Egress::baseUrlExpression).containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("track(java.lang.String)", "GET", "/shipments/{p2}",
                                "http://tracking:8081", "${tracking.url}"),
                        org.assertj.core.groups.Tuple.tuple("reroute(java.lang.String,java.lang.String)", "PATCH",
                                "/shipments/{p1}", "http://shipping:8080", null),
                        org.assertj.core.groups.Tuple.tuple("forward(java.lang.String,java.lang.String)", "*",
                                "/forwarded/{p1}", "http://shipping:8080", null),
                        org.assertj.core.groups.Tuple.tuple("anywhere(java.lang.String)", "GET", "?", null, null),
                        org.assertj.core.groups.Tuple.tuple("relay(java.net.http.HttpRequest)", "*", "?", null, null));
        assertThat(FixtureScans.path(jdk, "ingress:GET /elsewhere")).filteredOn(id -> id.startsWith("egress:"))
                .hasSize(2);
    }
}
