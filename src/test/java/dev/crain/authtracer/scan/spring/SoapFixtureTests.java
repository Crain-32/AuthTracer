package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0056: Spring Web Services' SOAP operations.
 */
class SoapFixtureTests {

    private static final String COUNTRIES = "?namespace:http://example.com/countries";
    private static final String GET = "ingress:SOAP getCountryRequest" + COUNTRIES;
    private static final String DELETE = "ingress:SOAP deleteCountryRequest" + COUNTRIES;
    private static final String DELETE_V2 = DELETE + "/v2";
    private static final String PING = "ingress:SOAP pingRequest?namespace:http://example.com/ping";

    @Test
    void operationsAreIngressBehindTheDispatchersPath() {
        ApplicationGraph graph = FixtureScans.scan("soap");
        // Each in its namespace: the same local part in another is its own Ingress, and an operation mapped in two
        // namespaces is two.
        assertThat(graph.nodes(Ingress.class)).filteredOn(SoapEndpoints::isSoap).extracting(Ingress::id)
                .containsExactlyInAnyOrder(GET, DELETE, GET + "/v2", DELETE_V2, DELETE + "/v3");
        assertThat(path(graph, DELETE_V2)).doesNotHaveDuplicates()
                .contains("location:METHOD:fixtures.soap.CountryEndpointV2#deleteCountry(java.lang.Object)"
                        + ":@PreAuthorize");
        assertThat(((Ingress) graph.node(GET).orElseThrow()).response().type()).isEqualTo("fixtures.soap.Country");
        List<AuthorizationLocation> delete = checks(graph, DELETE);
        assertThat(delete).extracting(AuthorizationLocation::mechanism)
                .containsExactly("authorizeHttpRequests", "@PreAuthorize");
        assertThat(delete.getFirst().routePattern()).isEqualTo("/ws/**");
        assertThat(delete.getFirst().requirement().authorities()).containsExactly("ROLE_PARTNER");
    }

    @Test
    void bootsDispatcherAtItsPath() {
        ApplicationGraph graph = FixtureScans.scan("soapboot");
        assertThat(graph.nodes(Ingress.class)).filteredOn(SoapEndpoints::isSoap).extracting(Ingress::id)
                .containsExactly(PING);
        assertThat(checks(graph, PING)).singleElement().satisfies(check ->
                assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED));
    }

    @Test
    void aDispatcherBeanRegisteredAsTheDefaultServlet() {
        // The servlet is a parameter: the registration's type argument says it is a MessageDispatcherServlet. At
        // "/", it answers whatever no other servlet maps.
        ApplicationGraph graph = FixtureScans.scan("soapdefault");
        assertThat(checks(graph, "ingress:SOAP quoteRequest?namespace:http://example.com/quotes")).singleElement().satisfies(check -> {
            assertThat(check.routePattern()).isEqualTo("anyRequest");
            assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
        });
    }

    @Test
    void aWsConfigurationSupportSubclassLeavesTheOperationsOffTheGraph() {
        ApplicationGraph graph = FixtureScans.scan("soapsupport");
        assertThat(graph.nodes(Ingress.class)).noneMatch(SoapEndpoints::isSoap);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .singleElement().satisfies(finding -> assertThat(finding.message())
                        .contains("fixtures.soapsupport.WsConfig"));
    }

    @Test
    void anOperationIsAsOpenAsTheDispatchersMostOpenPath() {
        // setServlet and addUrlMappings: the dispatcher answers at /ws/* (ROLE_PARTNER) and /soap/* (authenticated).
        ApplicationGraph graph = FixtureScans.scan("soappaths");
        List<AuthorizationLocation> checks = checks(graph, PING);
        assertThat(checks).extracting(AuthorizationLocation::routePattern).contains("/ws/**", "anyRequest");
        assertThat(checks).filteredOn(check -> check.id().equals("location:SPLIT:soap-paths:" + PING.substring(
                "ingress:".length())))
                .singleElement().satisfies(split -> {
                    assertThat(split.requirement().kind()).isEqualTo(Requirement.Kind.OR);
                    assertThat(split.requirement().operands()).extracting(Requirement::kind)
                            .containsExactly(Requirement.Kind.ANY_AUTHORITY, Requirement.Kind.AUTHENTICATED);
                });
    }

    @Test
    void aWebServiceTemplateCallLinksToTheOperationItsRequestNames() {
        ApplicationGraph client = FixtureScans.scan("soapclient");
        assertThat(path(client, "ingress:GET /countries")).map(id -> client.node(id).orElseThrow())
                .filteredOn(Egress.class::isInstance).map(Egress.class::cast).singleElement().satisfies(call -> {
                    assertThat(call.httpMethod() + " " + call.uriTemplate()).isEqualTo("SOAP getCountryRequest");
                    assertThat(call.query()).isEqualTo("namespace:http://example.com/countries");
                    assertThat(call.baseUrl()).isEqualTo("http://localhost:8080");
                });
        // Each client has its own default URI, from the bean method that builds it.
        assertThat(path(client, "ingress:GET /weather")).map(id -> client.node(id).orElseThrow())
                .filteredOn(Egress.class::isInstance).map(Egress.class::cast).singleElement()
                .satisfies(call -> assertThat(call.baseUrl()).isEqualTo("http://localhost:9090"));
        SystemGraph system = new Linker().link(List.of(client, FixtureScans.scan("soap")), ZipkinTraces.of(List.of()));
        // In its request's namespace only: the v2 operation of the same name isn't linked.
        assertThat(system.links()).extracting(Edge::to).filteredOn(to -> to.contains("getCountryRequest"))
                .containsExactly("soap/" + GET);
    }

    @Test
    void operationsMappedByTheirActionAreIngressNamedByIt() {
        ApplicationGraph graph = FixtureScans.scan("soapactions");
        assertThat(graph.nodes(Ingress.class)).filteredOn(SoapEndpoints::isSoap).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:SOAP http://example.com/orders/Cancel",
                        "ingress:SOAP http://example.com/orders/Track", "ingress:SOAP urn:Archive",
                        "ingress:SOAP urn:Purge", "ingress:SOAP statusRequest?namespace:http://example.com/orders",
                        "ingress:SOAP statusRequest?namespace:http://example.com/legacy");
        assertThat(checks(graph, "ingress:SOAP http://example.com/orders/Cancel"))
                .extracting(AuthorizationLocation::mechanism).containsExactly("authorizeHttpRequests", "@PreAuthorize");
    }

    @Test
    void wsSecuritysUsernameTokenIsAWayIn() {
        // The HTTP chain lets every SOAP request in; the interceptor's handler sets the Authentication the endpoint's
        // checks see, loading the user for each message.
        AuthoritySource source = FixtureScans.scan("soapactions").authoritySource();
        assertThat(source.detail()).contains("WS-Security UsernameToken (SOAP)");
        assertThat(source.freshness()).isEqualTo(AuthoritySource.Freshness.LIVE);
        // A user cache keeps what it loaded.
        AuthoritySource cached = FixtureScans.scan("soapwscache").authoritySource();
        assertThat(cached.detail()).contains("WS-Security UsernameToken (SOAP, user cache)");
        assertThat(cached.freshness()).isEqualTo(AuthoritySource.Freshness.SNAPSHOT);
    }

    @Test
    void aCallLinksByItsElementInItsNamespaceElseByItsAction() {
        ApplicationGraph client = FixtureScans.scan("soapactionclient");
        assertThat(egress(client, "ingress:GET /cancel")).singleElement().satisfies(call -> {
            // @XmlRootElement without a namespace: its package's @XmlSchema.
            assertThat(call.uriTemplate()).isEqualTo("cancelOrder");
            assertThat(call.query()).isEqualTo("namespace:http://example.com/orders"
                    + "&soapAction:http://example.com/orders/Cancel");
        });
        // A request typed Object names no element: the action is the operation.
        assertThat(egress(client, "ingress:GET /track")).extracting(Egress::uriTemplate)
                .containsExactly("http://example.com/orders/Track");
        SystemGraph system = new Linker().link(List.of(client, FixtureScans.scan("soapactions")),
                ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).filteredOn(to -> to.startsWith("soapactions/"))
                .containsExactlyInAnyOrder("soapactions/ingress:SOAP http://example.com/orders/Cancel",
                        "soapactions/ingress:SOAP http://example.com/orders/Track",
                        // A JAXBElement's QName: the operation of its namespace, not the legacy one.
                        "soapactions/ingress:SOAP statusRequest?namespace:http://example.com/orders");
    }

    @Test
    void aCallsUriIsItsOwnOrItsTemplateBeansDefault() {
        ApplicationGraph forms = FixtureScans.scan("soapforms");
        assertThat(egress(forms, "ingress:GET /quote")).singleElement().satisfies(call -> {
            // An @XmlRootElement without a name: the class's, decapitalized.
            assertThat(call.httpMethod() + " " + call.uriTemplate()).isEqualTo("SOAP getQuoteRequest");
            assertThat(call.baseUrl()).isEqualTo("http://quotes:8080");
        });
        assertThat(egress(forms, "ingress:GET /rates")).singleElement()
                .satisfies(call -> assertThat(call.baseUrl()).isEqualTo("http://rates:8080"));
        // Set from a @Value parameter of the bean method that builds the client.
        assertThat(egress(forms, "ingress:GET /holidays")).singleElement()
                .satisfies(call -> assertThat(call.baseUrl()).isEqualTo("http://holidays:8080"));
        // A configuration properties getter's, as Spring binds it.
        assertThat(egress(forms, "ingress:GET /payments")).singleElement().satisfies(call -> {
            assertThat(call.uriTemplate()).isEqualTo("getPaymentsRequest");
            assertThat(call.baseUrl()).isEqualTo("http://payments:8080");
        });
        // A request typed Object names no operation where it is sent, and XML sent as it is isn't read: operations
        // AuthTracer can't read (decision 0082), at the template's default URI.
        assertThat(egress(forms, "ingress:GET /forward")).extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactly(tuple("?", "http://rates:8080"));
        assertThat(egress(forms, "ingress:GET /raw")).extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactly(tuple("?", "http://rates:8080"));
        assertThat(forms.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("XML sent as it is"));
    }

    private static List<Egress> egress(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(Egress.class::isInstance).map(Egress.class::cast).toList();
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }

    @Test
    void withEnableWsBootRegistersNoDispatcherServlet() {
        ApplicationGraph enableWs = FixtureScans.scan("soapenablews");
        assertThat(enableWs.nodes(Ingress.class)).extracting(Ingress::id)
                .noneMatch(id -> id.startsWith("ingress:SOAP") || id.startsWith("ingress:POST /services"));
        assertThat(enableWs.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("WsConfig"));
    }
}
