package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0042: Spring Cloud OpenFeign clients as Egress.
 */
class FeignFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("feign");

    @Test
    void feignClientCalls() {
        List<Egress> egress = graph.nodes().stream().filter(Egress.class::isInstance).map(Egress.class::cast)
                .toList();
        assertThat(egress).extracting(Egress::client, Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("Feign", "GET", "/api/items/{id}", "http://localhost:8090"),
                        org.assertj.core.groups.Tuple.tuple("Feign", "POST", "/api/items", "http://localhost:8090"),
                        org.assertj.core.groups.Tuple.tuple("Feign", "GET", "/prices/{sku}", "http://pricing"),
                        org.assertj.core.groups.Tuple.tuple("Feign", "GET", "/reports/{id}", "http://reports"));
        assertThat(egress).filteredOn(call -> call.uriTemplate().equals("/api/items/{id}")).singleElement()
                .satisfies(call -> {
                    assertThat(call.response().type()).isEqualTo("fixtures.feign.Item");
                    // The RequestInterceptor bean relays the caller's token.
                    assertThat(call.credentials()).isEqualTo(Credentials.RELAY);
                });
    }

    @Test
    void fixedUrlsPlaceholderNamesContextIdsAndDefaultMethods() {
        ApplicationGraph forms = FixtureScans.scan("feignforms");
        assertThat(forms.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::baseUrlExpression)
                .containsOnly(tuple("/products/{id}", "http://localhost:8095", null),
                        tuple("/stock/{id}", "http://stock-service", "@FeignClient(name = \"${stock.service}\")"),
                        tuple("/audit/{id}", "http://localhost:8096", null));
        // A default method is no request, but the one it makes is.
        assertThat(path(forms, "ingress:GET /catalog/{id}/name")).filteredOn(id -> id.startsWith("egress:"))
                .singleElement().satisfies(id -> assertThat(id).endsWith("GET /products/{id}"));
        // A client's configuration that is a @Configuration is in every client's context: its fixed credentials
        // are every client's.
        assertThat(forms.nodes(Egress.class)).extracting(Egress::credentials).containsOnly(Credentials.STATIC);
    }

    @Test
    void openFeignsOAuth2SupportGivesEveryClientAToken() {
        assertThat(FixtureScans.scan("feignoauth2").nodes(Egress.class)).singleElement()
                .satisfies(call -> assertThat(call.credentials()).isEqualTo(Credentials.OAUTH2_CLIENT));
    }

    @Test
    void aClientsOwnConfigurationOnlyAppliesToIt() {
        List<Egress> egress = graph.nodes().stream().filter(Egress.class::isInstance).map(Egress.class::cast)
                .toList();
        assertThat(egress).filteredOn(call -> call.uriTemplate().equals("/reports/{id}")).singleElement()
                .extracting(Egress::credentials).isEqualTo(Credentials.OAUTH2_CLIENT);
        assertThat(egress).filteredOn(call -> !call.uriTemplate().equals("/reports/{id}"))
                .extracting(Egress::credentials).containsOnly(Credentials.RELAY);
    }
}
