package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0029: Spring for GraphQL operations.
 */
class GraphQlFixtureTests {

    private static final String SALARY_GUARD =
            "location:FIELD:graphql:fixtures.graphql.PersonGraphController#salary(fixtures.graphql.Person)";

    private final ApplicationGraph graph = FixtureScans.scan("graphql");

    @Test
    void operationsAreIngressWithTheirRootTypeAndField() {
        assertThat(graph.nodes(Ingress.class)).filteredOn(Ingress::graphQlOperation).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:QUERY person", "ingress:QUERY everyone", "ingress:MUTATION rename",
                        "ingress:QUERY version");
        Ingress person = (Ingress) graph.node("ingress:QUERY person").orElseThrow();
        assertThat(person.response().type()).isEqualTo("fixtures.graphql.Person");
        assertThat(((Ingress) graph.node("ingress:QUERY everyone").orElseThrow()).response().many()).isTrue();
    }

    @Test
    void theHttpRulesForTheGraphQlPathComeFirst() {
        // spring.graphql.http.path=/api/graphql: requests arrive there, not under anyRequest's denyAll.
        assertThat(rule(graph, "QUERY person").requirement().authorities()).containsExactly("SCOPE_graphql");
        assertThat(rule(graph, "QUERY person").routePattern()).isEqualTo("/api/graphql");
    }

    @Test
    void methodSecurityOnTheWay() {
        assertThat(path(graph, "ingress:QUERY person"))
                .contains("location:METHOD:fixtures.graphql.PersonService#find(long):@PreAuthorize");
        assertThat(path(graph, "ingress:MUTATION rename")).contains(
                "location:METHOD:fixtures.graphql.PersonGraphController#rename(long,java.lang.String):@PreAuthorize");
    }

    @Test
    void aResolverOfANonRootTypeGuardsItsField() {
        AuthorizationLocation salary = (AuthorizationLocation) graph.node(SALARY_GUARD).orElseThrow();
        assertThat(salary.scope()).isEqualTo(AuthorizationLocation.Scope.FIELD);
        assertThat(salary.guardedField()).isEqualTo("field:fixtures.graphql.Person.salary");
        assertThat(salary.requirement().authorities()).containsExactly("ROLE_HR");
        // Spring for GraphQL nulls a denied field and reports an error; the rest of the result is returned.
        assertThat(salary.denial().kind()).isEqualTo(AuthorizationLocation.Denial.Kind.NULL);
        assertThat(path(graph, "ingress:QUERY person")).contains(SALARY_GUARD);
        assertThat(path(graph, "ingress:QUERY everyone")).contains(SALARY_GUARD);
        assertThat(path(graph, "ingress:QUERY version")).doesNotContain(SALARY_GUARD);
    }

    @Test
    void resolvedFieldsAreExposedWithTheirOwnChecks() {
        Map<String, String> person = Exposures.of(graph).stream()
                .filter(exposure -> exposure.ingress().equals("ingress:QUERY person"))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
        assertThat(person.get("")).isEqualTo("SCOPE_graphql and ROLE_READER");
        assertThat(person.get("name")).isEqualTo(person.get(""));
        assertThat(person.get("salary")).isEqualTo("SCOPE_graphql and ROLE_READER and ROLE_HR");
        // Fields only a resolver adds: the batch's check, and what the manager resolver calls.
        assertThat(person.get("team")).isEqualTo("SCOPE_graphql and ROLE_READER and ROLE_TEAMS");
        assertThat(person.get("team.name")).isEqualTo(person.get("team"));
        assertThat(person.get("manager")).isEqualTo(person.get(""));
        assertThat(person.get("nickname")).isEqualTo(person.get(""));
        // The resolver's @Async check runs on another thread: it doesn't guard the field.
        assertThat(person.get("badge")).isEqualTo(person.get(""));
    }

    @Test
    void fieldsTheSchemaLeavesOutAreNotExposed() {
        // Team.budget is a Java property the schema doesn't declare: GraphQL never returns it.
        assertThat(Exposures.of(graph)).extracting(Exposures.Exposure::field).contains("team.name")
                .doesNotContain("team.budget");
        assertThat(((Field) graph.node("field:fixtures.graphql.Team.budget")
                .orElseThrow()).graphQl()).isFalse();
    }

    @Test
    void theSchemaParserReadsObjectTypesAndRoots() {
        GraphQlSchema schema = GraphQlSchema.parse("""
                schema { query: Root }
                type Root { me: User }
                extend type Root { users(first: Int = 10): [User!]! @auth(requires: "ADMIN") }
                type User implements Node & Named { id: ID! "The login" login: String }
                input UserInput { id: ID }
                enum Kind { A B }
                union Result = User
                directive @auth(requires: String) on FIELD_DEFINITION
                """);
        assertThat(schema.roots()).containsEntry("QUERY", "Root");
        assertThat(schema.types().get("Root")).containsExactly(Map.entry("me", "User"), Map.entry("users", "User"));
        assertThat(schema.types().get("User")).containsOnlyKeys("id", "login");
        assertThat(schema.types()).doesNotContainKeys("UserInput", "Kind");
    }

    @Test
    void theSchemaParserReadsFederatedTypesDescriptionsAndDirectives() {
        GraphQlSchema schema = GraphQlSchema.parse("""
                extend type Product @key(fields: "upc")
                type Product {
                  "The universal product code"
                  upc: String! @external
                  reviews: [Review] @requires(fields: "upc") @provides(fields: "author")
                  _service: Service
                }
                extend schema @link(url: "https://specs.apollo.dev/federation/v2.3")
                interface Review { body: String }
                """);
        assertThat(schema.types().get("Product")).containsExactly(Map.entry("upc", "String"),
                Map.entry("reviews", "Review"), Map.entry("_service", "Service"));
        assertThat(schema.types().get("Review")).containsOnlyKeys("body");
        assertThat(schema.roots()).containsEntry("QUERY", "Query");
    }

    @Test
    void anOperationIsAsOpenAsItsWeakerTransport() {
        // POST /graphql needs SCOPE_graphql; the WebSocket handshake GET /graphql-ws is permitAll.
        ApplicationGraph open = FixtureScans.scan("graphqlws");
        assertThat(endpoint(open, "ingress:QUERY greeting")).isEqualTo("none");
        assertThat(path(open, "ingress:QUERY greeting"))
                .contains("location:SPLIT:graphql-transports:QUERY greeting");
        // With an AuthenticationWebSocketInterceptor, the WebSocket needs an authenticated connection.
        ApplicationGraph authenticated = FixtureScans.scan("graphqlwsauth");
        assertThat(endpoint(authenticated, "ingress:QUERY greeting")).isEqualTo("authenticated");
    }

    @Test
    void withoutAWebSocketPathOnlyHttpCounts() {
        assertThat(path(graph, "ingress:QUERY version")).noneMatch(step -> step.startsWith("location:SPLIT"));
    }

    private static String endpoint(ApplicationGraph graph, String ingress) {
        return Exposures.of(graph).stream()
                .filter(exposure -> exposure.ingress().equals(ingress) && exposure.field().isEmpty())
                .map(Exposures.Exposure::requirement).findFirst().orElseThrow();
    }

    @Test
    void resolversReturningWrappersPrimitivesAndBatchesOfAMap() {
        ApplicationGraph books = FixtureScans.scan("graphqlbooks");
        Map<String, String> book = Exposures.of(books).stream()
                .filter(exposure -> exposure.ingress().equals("ingress:QUERY bookById"))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
        // Mono<Author>, List<Review>, an int, a Price read through the DataFetchingEnvironment of the named type,
        // and a batch's Mono<Map<Book, Publisher>>; authorId isn't in the schema.
        assertThat(book).containsOnlyKeys("", "id", "title", "author", "author.id", "author.name", "reviews",
                "reviews.text", "reviews.stars", "stock", "price", "price.currency", "price.amount", "publisher",
                "publisher.name");
        // Every check on the way through the resolver guards its field.
        assertThat(book.get("reviews")).isEqualTo("ROLE_MEMBER and ROLE_REVIEWER");
        assertThat(book.get("title")).isEqualTo("authenticated");
        // What a resolver calls is on the operation's path.
        assertThat(path(books, "ingress:QUERY books"))
                .contains("egress:fixtures.graphqlbooks.Inventory#stock(java.lang.String) GET /stock/{id}");
    }

    @Test
    void graphiqlAndTheSchemaWhenEnabled() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /graphiql",
                "ingress:GET /api/graphql/schema");
    }
}
