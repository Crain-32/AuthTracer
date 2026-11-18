package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Opaque;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A dynamic Groovy application (src/fixtures/groovy): calls are invokedynamic call sites resolved at run time.
 */
class GroovyFixtureTests {

    private static final String SERVICE = "location:METHOD:fixtures.groovydsl.";

    private final ApplicationGraph graph = FixtureScans.scan("groovydsl");

    @Test
    void closureRulesInOrder() {
        assertThat(rule("GET /info").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule("GET /info").routePattern()).isEqualTo("/health,/info");
        assertThat(rule("POST /items/{id}/reserve").requirement().authorities()).containsExactly("SCOPE_items.write");
        // AuthorizationManagers.anyOf(..) is varargs, which Groovy passes as separate arguments.
        assertThat(rule("GET /audit/log").requirement().kind()).isEqualTo(Kind.OR);
        assertThat(rule("GET /audit/log").requirement().operands()).flatExtracting(Requirement::authorities)
                .containsExactly("ROLE_AUDITOR", "ROLE_ADMIN");
        assertThat(rule("GET /items/{id}").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aCustomizerBeanWrittenAsAClosureComesFirst() {
        assertThat(rule("GET /status").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule("GET /status").routePattern()).isEqualTo("/status");
    }

    @Test
    void staticallyCompiledClosuresAndLambdas() {
        assertThat(rule("GET /reports/public").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule("GET /reports/daily").requirement().authorities()).containsExactly("ROLE_REPORTS");
        assertThat(rule("GET /exports/all").requirement().authorities()).containsExactly("ROLE_EXPORTS");
    }

    @Test
    void theClosureResourceServerIsTheAuthoritySource() {
        assertThat(graph.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.JWT_CLAIMS);
    }

    @Test
    void dynamicCallsOnTypedFieldsReachMethodSecurity() {
        assertThat(path(graph, "ingress:GET /items/{id}"))
                .contains(SERVICE + "ItemService#find(long):@PreAuthorize");
        assertThat(path(graph, "ingress:POST /items/{id}/reserve-static"))
                .contains(SERVICE + "StaticItemService#reserve(long):@PreAuthorize");
    }

    @Test
    void aDynamicCallOnThisSkipsTheProxy() {
        assertThat(path(graph, "ingress:GET /items/{id}/first"))
                .doesNotContain(SERVICE + "ItemService#find(long):@PreAuthorize");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("GET /items/{id}/first",
                        "ItemService#find(long)", "on this"));
    }

    @Test
    void anHttpInterfaceCalledDynamically() {
        Egress release = graph.nodes(Egress.class).stream()
                .filter(egress -> egress.uriTemplate().equals("/inventory/{id}/release")).findFirst().orElseThrow();
        assertThat(release.client()).isEqualTo("HTTP interface");
        assertThat(path(graph, "ingress:POST /items/{id}/release")).endsWith(release.id());
    }

    @Test
    void aDynamicRestClientChainIsTypedFromItsTypedField() {
        Egress reserve = graph.nodes(Egress.class).stream()
                .filter(egress -> egress.uriTemplate().equals("/inventory/{id}/reserve")).findFirst().orElseThrow();
        // client.post().uri(..).retrieve().body(String): typed from the RestClient field, call by call.
        assertThat(reserve.httpMethod()).isEqualTo("POST");
        assertThat(reserve.baseUrlExpression()).isEqualTo("${inventory.base-url}");
        assertThat(reserve.response().type()).isEqualTo("java.lang.String");
        assertThat(path(graph, "ingress:POST /items/{id}/reserve")).endsWith(reserve.id());
        assertThat(graph.nodes(Opaque.class)).isEmpty();
    }

    @Test
    void closuresInRequestCodeAreOnThePath() {
        assertThat(path(graph, "ingress:GET /items")).contains(
                "location:METHOD:fixtures.groovydsl.ItemService#find(long):@PreAuthorize");
    }

    @Test
    void aClosureCallingItsOwnerSkipsTheProxy() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /items/each: @PreAuthorize on "
                        + "fixtures.groovydsl.ItemService#find(long) is skipped"));
    }

    @Test
    void dynamicNamedArgumentConstructorsHaveLineage() {
        // new ItemView(id: item.id, supplier: item.supplierCode, ..) runs the no-argument constructor and setters.
        assertThat(graph.flows("ingress:GET /items/{id}")).contains(Flow.local("ingress:GET /items/{id}",
                "field:fixtures.groovydsl.Item.supplierCode", "field:fixtures.groovydsl.ItemView.supplier",
                FieldSource.DIRECT));
    }

    @Test
    void staticallyCompiledCodeHasEgressAndLineage() {
        Egress count = graph.nodes(Egress.class).stream()
                .filter(egress -> egress.uriTemplate().equals("/inventory/{id}/count")).findFirst().orElseThrow();
        assertThat(count.httpMethod()).isEqualTo("GET");
        assertThat(path(graph, "ingress:GET /static/items/{id}/count")).endsWith(count.id());
        // new ItemView(supplier: item.supplierCode, ..) compiles to setter calls.
        assertThat(graph.flows("ingress:GET /static/items/{id}")).contains(Flow.local("ingress:GET /static/items/{id}",
                "field:fixtures.groovydsl.Item.supplierCode", "field:fixtures.groovydsl.ItemView.supplier",
                FieldSource.DIRECT));
        // Jackson leaves out Groovy's getMetaClass().
        assertThat(graph.node("field:fixtures.groovydsl.ItemView.metaClass")).isEmpty();
    }

    @Test
    void untypedArgumentsFitTheTypedMethodAndClosuresKeepACallDynamic() {
        ApplicationGraph clients = FixtureScans.scan("groovyclients");
        // api.stock(sku) with a def sku: the interface's only stock(..).
        assertThat(path(clients, "ingress:GET /stock/{sku}")).filteredOn(id -> id.startsWith("egress:"))
                .singleElement().satisfies(id -> assertThat(id).endsWith("GET /stock/{sku}"));
        // template.execute(url, GET, null) { response -> .. }: the closure is the ResponseExtractor Groovy coerces
        // it to.
        assertThat(path(clients, "ingress:GET /legacy")).filteredOn(id -> id.startsWith("egress:"))
                .singleElement().satisfies(id -> assertThat(id).endsWith("GET /stock"));
        assertThat(clients.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH)
                .isEmpty();
    }

    private AuthorizationLocation rule(String ingress) {
        return FixtureScans.rule(graph, ingress);
    }
}
