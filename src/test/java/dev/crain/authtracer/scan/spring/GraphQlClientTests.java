package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0031: Spring for GraphQL client calls are Egress to the operation they send.
 */
class GraphQlClientTests {

    private final ApplicationGraph client = FixtureScans.scan("graphqlclient");

    @Test
    void aDocumentNamesTheOperationAndRootField() {
        Egress person = egress("/people/{id}");
        assertThat(person.client()).isEqualTo("GraphQlClient");
        assertThat(person.httpMethod()).isEqualTo("QUERY");
        assertThat(person.uriTemplate()).isEqualTo("person");
        assertThat(person.baseUrl()).isEqualTo("http://localhost:8095");
        assertThat(person.response().type()).isEqualTo("fixtures.graphqlclient.PersonView");
    }

    @Test
    void aNamedDocumentIsReadFromItsResourceAndAliasesAreResolved() {
        Egress rename = egress("/people/{id}/name");
        assertThat(rename.httpMethod()).isEqualTo("MUTATION");
        assertThat(rename.uriTemplate()).isEqualTo("rename");
        Egress everyone = egress("/everyone");
        assertThat(everyone.httpMethod()).isEqualTo("QUERY");
        assertThat(everyone.uriTemplate()).isEqualTo("everyone");
        assertThat(everyone.response().many()).isTrue();
    }

    @Test
    void aClientFromABeanMethodHasItsUrlAndCredentials() {
        Egress everyone = egress("/everyone");
        assertThat(everyone.baseUrl()).isEqualTo("http://localhost:8095");
        assertThat(everyone.credentials()).isEqualTo(Credentials.RELAY);
        assertThat(everyone.credentialsVia()).contains("ServletBearerExchangeFilterFunction");
    }

    @Test
    void callsLinkToTheCalledServicesOperations() {
        SystemGraph system = new Linker().link(List.of(client, FixtureScans.scan("graphql")),
                ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).contains("graphql/ingress:QUERY person",
                "graphql/ingress:MUTATION rename", "graphql/ingress:QUERY everyone");
        assertThat(system.links()).extracting(Edge::kind).containsOnly(Edge.Kind.NETWORK_INFERRED);
    }

    @Test
    void requestsWrittenInOtherWays() {
        ApplicationGraph forms = FixtureScans.scan("graphqlclientforms");
        // On a RestClient built with the URL; executed (no response path, no response type); a document name with no
        // resource, and a document AuthTracer can't read: any operation on the field the path names. With neither a
        // document nor a path, nothing says what is called: a field AuthTracer can't read (decision 0082).
        assertThat(forms.nodes(Egress.class)).extracting(egress -> egress.callSite().method(), Egress::httpMethod,
                Egress::uriTemplate, Egress::baseUrl, egress -> egress.response() == null ? null
                        : egress.response().type() + (egress.response().many() ? "[]" : ""))
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("person(long)", "QUERY", "person", "http://people:8095",
                                null),
                        org.assertj.core.groups.Tuple.tuple("everyone()", "*", "people", "http://people:8095",
                                "fixtures.graphqlclientforms.Person[]"),
                        org.assertj.core.groups.Tuple.tuple("named(java.lang.String)", "*", "person",
                                "http://people:8095", "java.lang.String"),
                        org.assertj.core.groups.Tuple.tuple("raw(java.lang.String)", "*", "?", "http://people:8095",
                                null),
                        // url(baseUrl + "/graphql"): the service is the configured base's.
                        org.assertj.core.groups.Tuple.tuple("team(long)", "QUERY", "team", "http://teams:8097",
                                "java.lang.String"));
        assertThat(forms.nodes(Egress.class)).filteredOn(egress -> egress.uriTemplate().equals("team"))
                .extracting(Egress::baseUrlExpression).containsExactly("${teams.base-url}/graphql");
    }

    private Egress egress(String route) {
        return client.path("ingress:" + (route.endsWith("name") ? "POST " : "GET ") + route).stream()
                .map(edge -> client.node(edge.to()).orElseThrow())
                .filter(Egress.class::isInstance).map(Egress.class::cast).findFirst().orElseThrow();
    }
}
