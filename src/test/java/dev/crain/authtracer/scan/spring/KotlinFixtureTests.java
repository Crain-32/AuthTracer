package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Kotlin applications (src/fixtures/kotlin): the Kotlin Security DSL, suspend functions and data classes.
 */
class KotlinFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("kotlindsl");

    @Test
    void theKotlinDslRulesInOrder() {
        assertThat(rule(graph, "GET /health").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /admin/stats").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(graph, "GET /admin/stats").routePattern()).isEqualTo("/admin/**");
        assertThat(rule(graph, "POST /orders/{id}/refund").requirement().authorities())
                .containsExactly("SCOPE_orders.write");
        // authorize({ request -> .. }, permitAll) comes before anyRequest and can't be evaluated: a request with the
        // X-Internal header gets permitAll, any other authenticated (HTTP-06).
        AuthorizationLocation orders = rule(graph, "GET /orders/{id}");
        assertThat(orders.requirement().kind()).isEqualTo(Kind.OR);
        assertThat(orders.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.PERMIT_ALL, Kind.AUTHENTICATED);
        assertThat(orders.routePattern()).isEqualTo("RequestMatcher or anyRequest");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .singleElement().satisfies(finding -> assertThat(finding.message())
                        .contains("The rule RequestMatcher (requires permitAll)"));
    }

    @Test
    void aServletPathReplacesTheBasePath() {
        // authorize("/ops/**", "/mvc", ..) matches /mvc/ops/**; this application's servlet path is /.
        assertThat(rule(graph, "GET /ops/status").routePattern()).endsWith("anyRequest");
    }

    @Test
    void dslBeansComeFirstInEveryKotlinDslChain() {
        AuthorizationLocation status = rule(graph, "GET /status/check");
        assertThat(status.requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(status.target().method()).isEqualTo("statusRules()");
        // The HttpSecurityDsl bean's rules come before the AuthorizeHttpRequestsDsl bean's.
        assertThat(rule(graph, "GET /internal/status").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        // Not in a chain configured with the Java DSL.
        assertThat(rule(graph, "GET /legacy/report").requirement().authorities()).containsExactly("ROLE_LEGACY");
    }

    @Test
    void theJavaDslWrittenInKotlin() {
        assertThat(rule(graph, "GET /legacy/report").requirement().authorities()).containsExactly("ROLE_LEGACY");
    }

    @Test
    void theKotlinDslResourceServerIsTheAuthoritySource() {
        assertThat(graph.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.JWT_CLAIMS);
        // jwt { } converts with Spring's defaults: scope to SCOPE_*, so no token carries a role.
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).anyMatch(message -> message.startsWith(
                        "authorizeHttpRequests on /admin/** asks for ROLE_ADMIN, which no request carries"));
    }

    @Test
    void suspendFunctionsAreCheckedOnceAndReturnTheirValue() {
        assertThat(path(graph, "ingress:GET /orders/{id}/customer")).containsExactly(
                rule(graph, "GET /orders/{id}/customer").id(),
                "location:METHOD:fixtures.kotlindsl.OrderService#customer(long,kotlin.coroutines.Continuation)"
                        + ":@PreAuthorize");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() != Finding.Kind.OPAQUE_CONFIG
                && finding.kind() != Finding.Kind.ALWAYS_DENIED);
        Ingress customer = (Ingress) graph.node("ingress:GET /orders/{id}/customer").orElseThrow();
        assertThat(customer.response().type()).isEqualTo("fixtures.kotlindsl.Customer");
    }

    @Test
    void dataClassFieldsTraceToTheirSources() {
        assertThat(graph.flows("ingress:GET /orders/{id}")).contains(
                Flow.local("ingress:GET /orders/{id}", "field:fixtures.kotlindsl.Order.cardNumber",
                        "field:fixtures.kotlindsl.OrderView.cardLast4", FieldSource.COMPUTED),
                Flow.local("ingress:GET /orders/{id}", "field:fixtures.kotlindsl.Order.customer",
                        "field:fixtures.kotlindsl.OrderView.customer", FieldSource.DIRECT));
    }

    @Test
    void restClientCallsInKotlin() {
        Egress refund = graph.nodes(Egress.class).getFirst();
        assertThat(refund.httpMethod()).isEqualTo("POST");
        assertThat(refund.uriTemplate()).isEqualTo("/payments/{id}/refund");
        assertThat(path(graph, "ingress:POST /orders/{id}/refund")).endsWith(refund.id());
    }

    @Test
    void theReactiveKotlinDsl() {
        ApplicationGraph reactive = FixtureScans.scan("kotlinreactive");
        assertThat(rule(reactive, "GET /public/info").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(reactive, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        // authorize("/reports/**") leaves out the access argument, which defaults to authenticated.
        assertThat(rule(reactive, "GET /reports/daily").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(reactive, "POST /teams/new").requirement().authorities())
                .containsExactly("SCOPE_teams.write");
        assertThat(rule(reactive, "GET /teams").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(reactive, "GET /teams").routePattern()).isEqualTo("anyExchange");
        assertThat(reactive.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.USER_DETAILS);
        assertThat(rule(reactive, "GET /ops/status").requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(rule(reactive, "GET /ops/status").target().method()).isEqualTo("opsRules()");
        // A suspend function under @EnableReactiveMethodSecurity (7.1.1 adapts coroutines to Mono).
        assertThat(path(reactive, "ingress:POST /teams/{id}/rename")).endsWith("location:METHOD:"
                + "fixtures.kotlinreactive.TeamService#rename(long,kotlin.coroutines.Continuation):@PreAuthorize");
        assertThat(reactive.findings()).isEmpty();
    }

    @Test
    void theKotlinRouterDsls() {
        assertThat(handler(graph, "GET /reports/{id}")).isEqualTo("ReportHandler#find");
        ApplicationGraph reactive = FixtureScans.scan("kotlinreactive");
        // router { "/directory".nest { GET("/teams", handler::list) } }: the reference compiles to a class.
        assertThat(handler(reactive, "GET /directory/teams")).isEqualTo("TeamHandler#list");
        assertThat(response(reactive, "GET /directory/teams")).isEqualTo("fixtures.kotlinreactive.Team");
        assertThat(handler(reactive, "POST /directory/teams")).isEqualTo("KotlinReactiveRoutes#routes$lambda$0$1");
        // coRouter { }: a suspend function reference, and a suspend lambda.
        assertThat(handler(reactive, "GET /co/teams/{id}")).isEqualTo("TeamHandler#find");
        assertThat(response(reactive, "GET /co/teams/{id}")).isEqualTo("fixtures.kotlinreactive.Team");
        assertThat(handler(reactive, "DELETE /co/teams/{id}")).isEqualTo("KotlinReactiveRoutes$coRoutes$1$2"
                + "#invokeSuspend");
    }

    @Test
    void theRouterDslsNestingPredicates() {
        ApplicationGraph routes = FixtureScans.scan("kotlinroutes");
        // path("/admin").nest { }: the predicate's pattern prefixes the nested routes.
        assertThat(handler(routes, "GET /admin/stats")).isEqualTo("AdminHandler#stats");
        // An open suspend function's body is its static $suspendImpl, where bodyValueAndAwait's value is.
        assertThat(response(routes, "GET /admin/stats")).isEqualTo("fixtures.kotlinroutes.Stats");
        // accept(..).nest { }: a predicate without a pattern adds nothing to the path.
        assertThat(handler(routes, "GET /profile")).isEqualTo("AdminHandler#profile");
        assertThat(response(routes, "GET /profile")).isEqualTo("fixtures.kotlinroutes.Profile");
        assertThat(routes.nodes().stream().filter(Ingress.class::isInstance).map(node -> ((Ingress) node).id()))
                .containsExactlyInAnyOrder("ingress:GET /admin/stats", "ingress:GET /profile");
    }

    @Test
    void lineageThroughBodyValueAndAwait() {
        ApplicationGraph reactive = FixtureScans.scan("kotlinreactive");
        assertThat(reactive.flows("ingress:GET /co/teams/{id}")).contains(Flow.local("ingress:GET /co/teams/{id}",
                "field:fixtures.kotlinreactive.Squad.label", "field:fixtures.kotlinreactive.Team.name",
                FieldSource.DIRECT));
    }

    private static String handler(ApplicationGraph graph, String ingress) {
        Ingress found = (Ingress) graph.node("ingress:" + ingress).orElseThrow();
        String type = found.handler().className();
        return type.substring(type.lastIndexOf('.') + 1) + "#" + found.handler().method().replaceAll("\\(.*", "");
    }

    private static String response(ApplicationGraph graph, String ingress) {
        return ((Ingress) graph.node("ingress:" + ingress).orElseThrow()).response().type();
    }
}
