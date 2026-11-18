package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.Set;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The other ways applications write where a call goes, each read to the service and path it names.
 */
class EgressUrlsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("egressurls");

    @Test
    void baseUrlsComeFromConfigurationPropertiesAsSpringBindsThem() {
        assertThat(graph.nodes(Egress.class)).filteredOn(egress -> egress.baseUrlExpression() != null
                && egress.baseUrlExpression().startsWith("${clients."))
                .extracting(egress -> egress.callSite().method(), Egress::uriTemplate, Egress::baseUrl,
                        Egress::baseUrlExpression)
                .containsExactlyInAnyOrder(
                        // A record's component, by its relaxed name, and one with a @DefaultValue no file overrides.
                        tuple("order(long)", "/orders/{id}", "http://orders:8080", "${clients.orders.base-url}"),
                        tuple("lines(long)", "/orders/{p2}/lines", "http://orders:8080", "${clients.orders.base-url}"),
                        tuple("fallbackOrder(long)", "/orders/{id}", "http://localhost:8070",
                                "${clients.orders.fallback-url}"),
                        // Nested JavaBeans: one set in the file, one keeping its field's initializer.
                        tuple("payment(long)", "/payments/{id}", "http://payments:8081", "${clients.payments.url}"),
                        tuple("stock(java.lang.String)", "/stock/{p2}", "http://localhost:8099",
                                "${clients.inventory.url}"));
        // A class a @Bean method binds gives a SOAP template its default URI.
        assertThat(egress("balance").baseUrl()).isEqualTo("http://ledger:8082");
    }

    @Test
    void pathSegmentsAreOneSegmentEach() {
        assertThat(egress("segments").uriTemplate()).isEqualTo("/orders/{p2}/lines");
        assertThat(egress("segments").baseUrl()).isEqualTo("http://orders:8080");
        assertThat(egress("lines").uriTemplate()).isEqualTo("/orders/{p2}/lines");
    }

    @Test
    void aHostGivenAsAUriVariableIsTheValueItHolds() {
        assertThat(egress("byHost")).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::baseUrlExpression)
                .containsExactly("/orders/{id}", "http://orders:8080", "http://${orders.host}:8080");
        assertThat(egress("byNamedHost")).extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactly("/orders/{id}/notes", "http://orders:8080");
        // A leading variable holds the whole base URL.
        assertThat(egress("viaGateway")).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::baseUrlExpression)
                .containsExactly("/orders/{id}", "http://gateway:8090", "${gateway.url}");
        // One AuthTracer doesn't know names no service: the path is still read.
        assertThat(egress("anyHost")).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::baseUrlExpression)
                .containsExactly("/orders/{id}/audit", null, "http://{host}:8080");
    }

    @Test
    void urlsBuiltWithStringBuildersAndFormatsAreRead() {
        assertThat(graph.nodes(Egress.class)).filteredOn(egress -> Set.of("built", "appended", "formatted",
                "formattedText", "indexed").contains(egress.callSite().method().split("\\(")[0]))
                .extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactlyInAnyOrder(tuple("/orders/{p2}/history", "http://orders:8080"),
                        tuple("/orders/{p2}/status", "http://orders:8080"),
                        tuple("/orders/{p2}/items", "http://orders:8080"),
                        tuple("/orders/{p2}/totals", "http://orders:8080"),
                        tuple("/orders/{p2}/refunds", "http://orders:8080"));
        // Indexed specifiers take their own argument, and %% is a percent sign.
        assertThat(egress("indexed").query()).isEqualTo("rate=5%");
    }

    @Test
    void aRequestEntityMadeWithNewCarriesItsMethodAndUrl() {
        assertThat(egress("create")).extracting(Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl,
                egress -> egress.response().type()).containsExactly("POST", "/orders", "http://orders:8080",
                        "fixtures.egressurls.Receipt");
    }

    @Test
    void httpInterfacesAGenericHelperCreatesHaveTheBaseUrlTheirBeanGivesIt() {
        assertThat(graph.nodes(Egress.class)).filteredOn(egress -> egress.client().equals("HTTP interface"))
                .extracting(Egress::uriTemplate, Egress::baseUrl, Egress::baseUrlExpression)
                .containsExactlyInAnyOrder(tuple("/stock/{sku}", "http://stock:8080", null),
                        tuple("/prices/{sku}", "http://prices:8083", "${prices.url}"));
    }

    @Test
    void aMethodReferenceToAnHttpInterfaceOrFeignMethodIsTheCall() {
        assertThat(path(graph, "ingress:GET /stock")).contains(egressAt("stock(java.util.List)").id());
        assertThat(path(graph, "ingress:GET /prices")).contains(egressAt("prices(java.util.List)").id());
        assertThat(path(graph, "ingress:GET /products")).contains(egressAt("products(java.util.List)").id());
    }

    @Test
    void feignsBasicAuthInterceptorSendsFixedCredentials() {
        assertThat(egressAt("products(java.util.List)")).extracting(Egress::client, Egress::uriTemplate,
                Egress::credentials, Egress::credentialsVia)
                .containsExactly("Feign", "/products/{id}", Credentials.STATIC, "BasicAuthRequestInterceptor");
    }

    @Test
    void soapRequestsWrappedInAJaxbElementNameTheirElement() {
        assertThat(graph.nodes(Egress.class)).filteredOn(egress -> egress.client().equals("WebServiceTemplate"))
                .extracting(Egress::uriTemplate, Egress::baseUrl, Egress::query)
                .containsExactlyInAnyOrder(
                        // An ObjectFactory method's @XmlElementDecl, a QName made at the call or held in a field.
                        tuple("getCountryRequest", "http://countries:8080", "namespace:http://example.com/countries"),
                        tuple("getCapitalRequest", "http://countries:8080", "namespace:http://example.com/countries"),
                        tuple("getBalanceRequest", "http://ledger:8082", "namespace:http://example.com/ledger"),
                        tuple("getRegionRequest", "http://countries:8080", "namespace:http://example.com/countries"));
    }

    @Test
    void nothingIsLeftUnread() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG).isEmpty();
        assertThat(graph.nodes(Egress.class)).noneMatch(egress -> egress.uriTemplate().equals(Egress.UNKNOWN_TARGET));
    }

    private Egress egress(String method) {
        return graph.nodes(Egress.class).stream().filter(egress -> egress.callSite().method().startsWith(method + "("))
                .reduce((first, second) -> {
                    throw new AssertionError("more than one Egress in " + method);
                }).orElseThrow(() -> new AssertionError("no Egress in " + method + ": " + graph.nodes(Egress.class)));
    }

    private Egress egressAt(String method) {
        return graph.nodes(Egress.class).stream().filter(egress -> egress.callSite().method().equals(method))
                .findFirst().orElseThrow(() -> new AssertionError("no Egress in " + method));
    }
}
