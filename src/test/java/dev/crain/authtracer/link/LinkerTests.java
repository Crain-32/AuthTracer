package dev.crain.authtracer.link;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.IdentityUsage;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Observation;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import org.assertj.core.groups.Tuple;
import org.junit.jupiter.api.Test;

class LinkerTests {

    private static final Egress GET_ITEM = Egress.of("RestClient", "GET", "/items/{id}", "http://localhost:9001",
            null, CodeRef.ofMethod("front.ItemClient", "get(long)"), new Payload("front.ItemDto", false));
    private static final Ingress ITEM = Ingress.of("GET", "/items/{itemId}", CodeRef.ofMethod("back.Items", "get(long)"))
            .withResponse(new Payload("back.Item", false));
    private static final AuthorizationLocation ITEM_READ = location("location:METHOD:back.Items#get:@PreAuthorize",
            AuthorizationLocation.Scope.METHOD, Requirement.anyAuthority(List.of("SCOPE_items.read"))
                    .withSource("hasAuthority('SCOPE_items.read')"));
    private static final Map<String, String> ITEM_ROUTE = Map.of("method", "GET", "uri", "/items/{itemId}");
    private static final AuthorizationLocation ANY_REQUEST = location("location:HTTP_REQUEST:back.Config:0:anyRequest",
            AuthorizationLocation.Scope.HTTP_REQUEST, Requirement.authenticated());

    private final ApplicationGraph front = graph("front", 9000, List.of(GET_ITEM,
            Field.of("front.ItemDto", "name", "name", "java.lang.String"),
            Field.of("front.ItemDto", "price", "cost", "java.math.BigDecimal")), List.of());
    private final ApplicationGraph back = graph("back", 9001, List.of(ITEM, ITEM_READ, ANY_REQUEST,
            Field.of("back.Item", "name", "name", "java.lang.String"),
            Field.of("back.Item", "price", "cost", "java.math.BigDecimal")),
            List.of(Edge.local(ITEM.id(), ITEM.id(), ANY_REQUEST.id(), 1, List.of()),
                    Edge.local(ITEM.id(), ANY_REQUEST.id(), ITEM_READ.id(), 2, List.of())));

    @Test
    void infersLinksFromTemplateMethodAndPort() {
        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of()));
        assertThat(system.links()).singleElement().satisfies(link -> {
            assertThat(link.kind()).isEqualTo(Edge.Kind.NETWORK_INFERRED);
            assertThat(link.from()).isEqualTo("front/" + GET_ITEM.id());
            assertThat(link.to()).isEqualTo("back/" + ITEM.id());
            assertThat(link.bidirectional()).isTrue();
        });
    }

    @Test
    void wrongPortIsNotALink() {
        ApplicationGraph elsewhere = graph("back", 7777, back.nodes(), back.edges());
        assertThat(new Linker().link(List.of(front, elsewhere), ZipkinTraces.of(List.of())).links()).isEmpty();
    }

    @Test
    void fieldsCrossLinksByJsonName() {
        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of()));
        assertThat(system.flows()).extracting(Flow::from, Flow::to).containsExactlyInAnyOrder(
                org.assertj.core.groups.Tuple.tuple("back/field:back.Item.name", "front/field:front.ItemDto.name"),
                org.assertj.core.groups.Tuple.tuple("back/field:back.Item.price", "front/field:front.ItemDto.price"));
        assertThat(system.flows()).allSatisfy(flow -> assertThat(flow.kind()).isEqualTo(Flow.Kind.NETWORK));
    }

    @Test
    void tracesConfirmLinksAndChecks() {
        List<TraceSpan> trace = List.of(
                span("1", null, "SERVER", "http get /orders", "front", Map.of("method", "GET", "uri", "/orders")),
                span("2", "1", "CLIENT", "http get", "front",
                        Map.of("method", "GET", "uri", "/items/{id}", "http.url", "http://localhost:9001/items/7")),
                span("3", "2", "SERVER", "http get /items/{itemId}", "back",
                        Map.of("method", "GET", "uri", "/items/{itemId}")),
                decision("4", "3", "authorize request", "true", "AuthorizationDecision [granted=true]"),
                decision("5", "3", "authorize method", "true",
                        "ExpressionAuthorizationDecision [granted=true, expressionAttribute=hasAuthority('SCOPE_items.read')]"),
                decision("6", "3", "authorize method", "false",
                        "ExpressionAuthorizationDecision [granted=false, expressionAttribute=hasRole('ROOT')]"));

        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).singleElement().extracting(Edge::kind).isEqualTo(Edge.Kind.NETWORK_OBSERVED);
        assertThat(system.observation("back/" + ITEM_READ.id())).hasValueSatisfying(observation -> {
            assertThat(observation.granted()).isEqualTo(1);
            assertThat(observation.denied()).isZero();
        });
        assertThat(system.observation("back/" + ANY_REQUEST.id())).hasValueSatisfying(observation -> {
            assertThat(observation.granted()).isEqualTo(1);
            assertThat(observation.denied()).isZero();
        });
        assertThat(system.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.RUNTIME_ONLY_CHECK);
            assertThat(finding.message()).contains("hasRole('ROOT')");
        });
    }

    @Test
    void webFluxRequestDecisionsAreNamedAfterTheExchange() {
        List<TraceSpan> trace = List.of(
                span("3", null, "SERVER", "http get /items/{itemId}", "back",
                        Map.of("method", "GET", "uri", "/items/{itemId}")),
                decision("4", "3", "authorize exchange", "false", "AuthorizationDecision [granted=false]"));
        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(trace)));
        assertThat(system.observation("back/" + ANY_REQUEST.id())).hasValueSatisfying(observation ->
                assertThat(observation.denied()).isEqualTo(1));
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void requestsDeniedBeforeRoutingMatchByUrlPath() {
        List<TraceSpan> trace = List.of(
                span("2", null, "CLIENT", "http get", "front",
                        Map.of("method", "GET", "uri", "/items/{id}", "http.url", "http://localhost:9001/items/7")),
                span("3", "2", "SERVER", "http get", "back", Map.of("method", "GET", "http.url", "/items/7")));
        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(trace)));
        assertThat(system.links()).singleElement().extracting(Edge::kind).isEqualTo(Edge.Kind.NETWORK_OBSERVED);
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void callsWithoutAStaticCounterpartAreFindings() {
        List<TraceSpan> trace = List.of(
                span("2", null, "CLIENT", "http get", "front",
                        Map.of("method", "DELETE", "uri", "/items/{id}", "http.url", "http://localhost:9001/items/7")),
                span("3", "2", "SERVER", "http delete", "back", Map.of("method", "DELETE", "http.url", "/items/7")));
        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(trace)));
        assertThat(system.findings()).singleElement().extracting(Finding::kind).isEqualTo(Finding.Kind.UNMATCHED_CALL);
    }

    @Test
    void identitiesKeepWhatTheirChecksNeeded() {
        String granted = "[SCOPE_items.read, FactorGrantedAuthority [authority=FACTOR_BEARER,"
                + " issuedAt=2026-10-16T02:03:30Z], SCOPE_items.write]";
        List<TraceSpan> read = List.of(
                span("3", null, "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE),
                identified("4", "3", "authorize request", "true", "AuthorizationDecision [granted=true]", granted),
                identified("5", "3", "authorize method", "true", "ExpressionAuthorizationDecision [granted=true,"
                        + " expressionAttribute=hasAuthority('SCOPE_items.read')]", granted));
        // The same identity: Spring lists the authorities in any order, with a new factor timestamp each time.
        List<TraceSpan> denied = List.of(
                span("13", null, "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE),
                identified("14", "13", "authorize request", "false", "AuthorizationDecision [granted=false]",
                        "[SCOPE_items.write, FactorGrantedAuthority [authority=FACTOR_BEARER,"
                                + " issuedAt=2026-10-16T09:00:00Z], SCOPE_items.read]"));
        List<TraceSpan> anonymous = List.of(
                span("23", null, "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE),
                span("24", "23", null, "authorize request", "back", Map.of(
                        "spring.security.authorization.decision", "false",
                        "spring.security.authorization.decision.details", "AuthorizationDecision [granted=false]",
                        "spring.security.authentication.type", "AnonymousAuthenticationToken",
                        "spring.security.authentication.authorities", "[ROLE_ANONYMOUS]")));

        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(read, denied, anonymous)));

        assertThat(system.identities()).singleElement().satisfies(identity -> {
            assertThat(identity.authenticationType()).isEqualTo("JwtAuthenticationToken");
            assertThat(identity.authorities()).containsExactly("SCOPE_items.read", "SCOPE_items.write");
            assertThat(identity.requests()).isEqualTo(2);
            assertThat(identity.endpoints()).containsExactly("back GET /items/{itemId}");
            assertThat(identity.needed()).containsExactly("SCOPE_items.read");
            assertThat(identity.unneeded()).containsExactly("SCOPE_items.write");
            assertThat(identity.denied()).isEqualTo(1);
            assertThat(identity.unread()).isZero();
        });
    }

    @Test
    void checksAuthTracerCantReadMightNeedAnything() {
        AuthorizationLocation owner = location("location:METHOD:back.Items#get:@PostAuthorize",
                AuthorizationLocation.Scope.METHOD,
                Requirement.expression("returnObject.owner == authentication.name"));
        ApplicationGraph owned = graph("back", 9001, List.of(ITEM, owner),
                List.of(Edge.local(ITEM.id(), ITEM.id(), owner.id(), 1, List.of())));
        List<TraceSpan> trace = List.of(
                span("3", null, "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE),
                identified("4", "3", "authorize method", "true", "ExpressionAuthorizationDecision [granted=true,"
                        + " expressionAttribute=returnObject.owner == authentication.name]", "[SCOPE_items.read]"));
        SystemGraph system = new Linker().link(List.of(owned), ZipkinTraces.of(List.of(trace)));
        assertThat(system.identities()).singleElement().satisfies(identity -> {
            assertThat(identity.unneeded()).containsExactly("SCOPE_items.read");
            assertThat(identity.unread()).isEqualTo(1);
        });
    }

    @Test
    void roleChecksMatchThroughTheRoleHierarchy() {
        // hasRole('USER') with ROLE_ADMIN > ROLE_USER: the graph lists both roles, Spring's decision names ROLE_USER.
        AuthorizationLocation users = location("location:METHOD:back.Items#get:@PreAuthorize",
                AuthorizationLocation.Scope.METHOD, Requirement.anyAuthority(List.of("ROLE_USER", "ROLE_ADMIN")));
        ApplicationGraph hierarchy = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "back", "test", 9001,
                AuthoritySource.UNKNOWN.withRoleHierarchy(new TreeMap<>(Map.of("ROLE_ADMIN",
                        new TreeSet<>(Set.of("ROLE_USER")), "ROLE_OPS", new TreeSet<>(Set.of("ROLE_SUPPORT"))))),
                List.of(ITEM, users), List.of(Edge.local(ITEM.id(), ITEM.id(), users.id(), 1, List.of())), List.of(),
                List.of(), List.of());
        List<TraceSpan> trace = List.of(
                span("3", null, "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE),
                identified("4", "3", "authorize method", "true",
                        "AuthorityAuthorizationDecision [granted=true, authorities=[ROLE_USER]]", "[ROLE_ADMIN]"));

        SystemGraph system = new Linker().link(List.of(hierarchy), ZipkinTraces.of(List.of(trace)));

        assertThat(system.findings()).isEmpty();
        assertThat(system.observation("back/" + users.id())).hasValueSatisfying(observation ->
                assertThat(observation.granted()).isEqualTo(1));
        // The admin got in through the hierarchy, so its role was needed.
        assertThat(system.identities()).singleElement().extracting(IdentityUsage::needed)
                .isEqualTo(List.of("ROLE_ADMIN"));
    }

    @Test
    void grantedAuthoritiesAreReadFromSpringsListOfThem() {
        assertThat(Identities.granted("[b, FactorGrantedAuthority [authority=FACTOR_X, issuedAt=t], a]"))
                .containsExactly("a", "b");
        assertThat(Identities.granted("[OidcUserAuthority [authority=OIDC_USER, attributes={a=1}], SCOPE_x]"))
                .containsExactly("OIDC_USER", "SCOPE_x");
        assertThat(Identities.granted("[]")).isEmpty();
    }

    @Test
    void grpcSpansLinkByTheirFullMethodName() {
        Egress call = Egress.of("gRPC", "GRPC", "shop.Greeter/SayHello", null, "static://localhost:9090",
                CodeRef.ofMethod("front.Greeting", "greet()"), null);
        Ingress rpc = Ingress.of("GRPC", "shop.Greeter/SayHello", CodeRef.ofMethod("back.Greeter", "sayHello()"));
        Ingress other = Ingress.of("GRPC", "shop.Greeter/Ping", CodeRef.ofMethod("back.Greeter", "ping()"));
        ApplicationGraph caller = graph("front", 9000, List.of(call), List.of());
        ApplicationGraph callee = graph("back", 9001, List.of(rpc, other), List.of());
        Map<String, String> tags = Map.of("rpc.system", "grpc", "rpc.service", "shop.Greeter",
                "rpc.method", "SayHello");
        List<TraceSpan> trace = List.of(span("1", null, "CLIENT", "shop.greeter/sayhello", "front", tags),
                span("2", "1", "SERVER", "shop.greeter/sayhello", "back", tags));

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).singleElement().satisfies(link -> {
            assertThat(link.kind()).isEqualTo(Edge.Kind.NETWORK_OBSERVED);
            assertThat(link.to()).isEqualTo("back/" + rpc.id());
        });
    }

    @Test
    void graphQlCallsLinkByTheOperationTheServerRan() {
        // As a Spring Boot 4.1.1 service traces them: both sides are POST /graphql; Spring for GraphQL's observations
        // under the server span name the operation and its root field.
        Egress call = Egress.of("GraphQlClient", "QUERY", "person", "http://localhost:9001", null,
                CodeRef.ofMethod("front.People", "get()"), null);
        Ingress person = Ingress.of("QUERY", "person", CodeRef.ofMethod("back.People", "person()"));
        Ingress everyone = Ingress.of("QUERY", "everyone", CodeRef.ofMethod("back.People", "everyone()"));
        ApplicationGraph caller = graph("front", 9000, List.of(call), List.of());
        ApplicationGraph callee = graph("back", 9001, List.of(person, everyone), List.of());
        List<TraceSpan> trace = List.of(
                span("1", null, "CLIENT", "http post", "front", Map.of("method", "POST",
                        "http.url", "http://localhost:9001/graphql", "uri", "none")),
                span("2", "1", "SERVER", "http post /graphql", "back", Map.of("method", "POST", "uri", "/graphql")),
                span("3", "2", null, "graphql query", "back", Map.of("graphql.operation.type", "query")),
                span("4", "2", null, "graphql field person", "back", Map.of("graphql.field.name", "person",
                        "graphql.field.path", "/person")));

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).filteredOn(link -> link.kind() == Edge.Kind.NETWORK_OBSERVED).singleElement()
                .satisfies(link -> assertThat(link.to()).isEqualTo("back/" + person.id()));
        assertThat(system.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.UNMATCHED_CALL);
    }

    @Test
    void aGatewayRouteLinksToEveryEndpointUnderIt() {
        // Decision 0043: the route forwards /items/** to back, which serves two endpoints there and one elsewhere.
        Egress route = Egress.of("Gateway", "GET", "/items/**", "http://localhost:9001", null,
                CodeRef.ofClass("application properties"), null);
        ApplicationGraph gateway = graph("gateway", 9000, List.of(route), List.of());
        Ingress items = Ingress.of("GET", "/items", CodeRef.ofMethod("back.Items", "list()"));
        Ingress other = Ingress.of("GET", "/orders/{id}", CodeRef.ofMethod("back.Orders", "get(long)"));
        ApplicationGraph service = graph("back", 9001, List.of(ITEM, items, other), List.of());

        SystemGraph system = new Linker().link(List.of(gateway, service), ZipkinTraces.of(List.of()));

        assertThat(system.links()).extracting(Edge::to).containsExactlyInAnyOrder("back/" + ITEM.id(),
                "back/" + items.id());
    }

    @Test
    void aHostThatNamesAServiceIsThatService() {
        // http://back through discovery: no port to go by, but the name says which service.
        Egress route = Egress.of("Gateway", "*", "/**", "http://back", null, CodeRef.ofClass("application properties"),
                null);
        ApplicationGraph gateway = graph("gateway", 9000, List.of(route), List.of());
        Ingress orders = Ingress.of("GET", "/orders/{id}", CodeRef.ofMethod("other.Orders", "get(long)"));
        ApplicationGraph other = graph("other", 9002, List.of(orders), List.of());

        SystemGraph system = new Linker().link(List.of(gateway, back, other), ZipkinTraces.of(List.of()));

        assertThat(system.links()).extracting(Edge::to).isNotEmpty().allMatch(to -> to.startsWith("back/"));
        // A service outside the system links to nothing.
        Egress elsewhere = Egress.of("Gateway", "*", "/**", "http://genai", null,
                CodeRef.ofClass("application properties"), null);
        assertThat(new Linker().link(List.of(graph("gateway", 9000, List.of(elsewhere), List.of()), back, other),
                ZipkinTraces.of(List.of())).links()).isEmpty();
    }

    /**
     * A service that sets no server.port listens on Spring Boot's 8080: a call to an outside API (443) isn't to it,
     * and a cluster-local name of a service is that service.
     */
    @Test
    void anOutsideHostIsNoServiceOfTheSystemAndAClusterNameIsTheServiceItNames() {
        Ingress orders = Ingress.of("GET", "/v1/charges", CodeRef.ofMethod("payments.Charges", "list()"));
        ApplicationGraph payments = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "payments", "test", null,
                AuthoritySource.UNKNOWN, List.of(orders), List.of(), List.of(), List.of(), List.of());
        Egress stripe = Egress.of("RestClient", "GET", "/v1/charges", "https://api.stripe.com", null,
                CodeRef.ofMethod("shop.Billing", "charges()"), null);
        Egress cluster = Egress.of("RestClient", "GET", "/v1/charges",
                "http://payments.default.svc.cluster.local", null, CodeRef.ofMethod("shop.Billing", "own()"), null);

        assertThat(new Linker().link(List.of(graph("shop", 9000, List.of(stripe), List.of()), payments),
                ZipkinTraces.of(List.of())).links()).isEmpty();
        assertThat(new Linker().link(List.of(graph("shop", 9000, List.of(cluster), List.of()), payments),
                ZipkinTraces.of(List.of())).links()).extracting(Edge::to).containsExactly("payments/" + orders.id());
    }

    @Test
    void aTracedCallLandsOnTheEndpointItsQuerySelects() {
        // Spring routes ?use_case=delegation to the mapping with that param, the rest to the plain one.
        Egress call = Egress.of("RestClient", "GET", "/user/messages", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Messages", "get()"), null);
        Ingress plain = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "mine()"));
        Ingress delegated = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "delegated()"))
                .andParams("use_case=delegation");
        AuthorizationLocation mine = location("location:METHOD:back.Messages#mine", AuthorizationLocation.Scope.METHOD,
                Requirement.anyAuthority(List.of("SCOPE_messages")).withSource("hasAuthority('SCOPE_messages')"));
        AuthorizationLocation delegation = location("location:METHOD:back.Messages#delegated",
                AuthorizationLocation.Scope.METHOD, Requirement.anyAuthority(List.of("SCOPE_delegate"))
                        .withSource("hasAuthority('SCOPE_delegate')"));
        ApplicationGraph caller = graph("front", 9000, List.of(call), List.of());
        ApplicationGraph callee = graph("back", 9001, List.of(plain, delegated, mine, delegation),
                List.of(Edge.local(plain.id(), plain.id(), mine.id(), 1, List.of()),
                        Edge.local(delegated.id(), delegated.id(), delegation.id(), 1, List.of())));
        List<TraceSpan> trace = List.of(
                span("1", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/user/messages",
                        "http.url", "http://localhost:9001/user/messages?use_case=delegation")),
                span("2", "1", "SERVER", "http get /user/messages", "back",
                        Map.of("method", "GET", "uri", "/user/messages")),
                decision("3", "2", "authorize method", "true", "ExpressionAuthorizationDecision [granted=true,"
                        + " expressionAttribute=hasAuthority('SCOPE_delegate')]"));

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).filteredOn(link -> link.kind() == Edge.Kind.NETWORK_OBSERVED).singleElement()
                .extracting(Edge::to).isEqualTo("back/" + delegated.id());
        assertThat(system.observation("back/" + delegation.id())).hasValueSatisfying(observation ->
                assertThat(observation.granted()).isEqualTo(1));
        assertThat(system.findings()).isEmpty();

        // A server span alone doesn't record the query: neither endpoint is credited with its decisions.
        SystemGraph unsure = new Linker().link(List.of(callee), ZipkinTraces.of(List.of(trace.subList(1, 3))));
        assertThat(unsure.observations()).isEmpty();
        assertThat(unsure.findings()).isEmpty();
    }

    @Test
    void aCallToALiteralPathLandsOnThatRouteBeforeAVariableOne() {
        Egress me = Egress.of("RestClient", "GET", "/items/mine", "http://localhost:9001", null,
                CodeRef.ofMethod("front.ItemClient", "mine()"), null);
        Egress other = Egress.of("RestClient", "GET", "/items/latest", "http://localhost:9001", null,
                CodeRef.ofMethod("front.ItemClient", "latest()"), null);
        Ingress mine = Ingress.of("GET", "/items/mine", CodeRef.ofMethod("back.Items", "mine()"));
        ApplicationGraph caller = graph("front", 9000, List.of(me, other), List.of());
        ApplicationGraph callee = graph("back", 9001, List.of(ITEM, mine), List.of());

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of()));

        assertThat(system.linksFrom("front/" + me.id())).extracting(Edge::to).containsExactly("back/" + mine.id());
        // No route names "latest": the variable route takes it.
        assertThat(system.linksFrom("front/" + other.id())).extracting(Edge::to).containsExactly("back/" + ITEM.id());
    }

    @Test
    void typesThatHoldThemselvesLinkEachFieldOnce() {
        // An org chart: an employee's manager, mentor and reports are employees, and so are a team's lead and members.
        // Following every way round those cycles, five levels deep, would be millions of flows: a pair of types is
        // matched once.
        String[][] properties = { { "Employee", "name", "String" }, { "Employee", "team", "Team" },
                { "Team", "lead", "Employee" }, { "Team", "members", "Employee[]" },
                { "Employee", "manager", "Employee" }, { "Employee", "skipManager", "Employee" },
                { "Employee", "mentor", "Employee" }, { "Employee", "buddy", "Employee" },
                { "Employee", "backup", "Employee" }, { "Employee", "delegate", "Employee" },
                { "Employee", "approver", "Employee" }, { "Employee", "hrPartner", "Employee" },
                { "Employee", "reports", "Employee[]" }, { "Employee", "peers", "Employee[]" },
                { "Employee", "assistant", "Employee" }, { "Employee", "successor", "Employee" },
                { "Employee", "mentees", "Employee[]" }, { "Employee", "interviewers", "Employee[]" } };
        Egress call = Egress.of("RestClient", "GET", "/employees/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Directory", "get(long)"), new Payload("front.EmployeeDto", false));
        Ingress employee = Ingress.of("GET", "/employees/{id}", CodeRef.ofMethod("back.Employees", "get(long)"))
                .withResponse(new Payload("back.Employee", false));
        List<Node> frontNodes = new ArrayList<>(List.of(call));
        List<Node> backNodes = new ArrayList<>(List.of(employee));
        List<Tuple> carried = new ArrayList<>();
        for (String[] property : properties) {
            String type = property[2].replace("[]", "");
            String many = property[2].endsWith("[]") ? "[]" : "";
            Field local = Field.of("front." + property[0] + "Dto", property[1], property[1], type.equals("String")
                    ? "java.lang.String" : "front." + type + "Dto" + many);
            Field remote = Field.of("back." + property[0], property[1], property[1], type.equals("String")
                    ? "java.lang.String" : "back." + type + many);
            frontNodes.add(local);
            backNodes.add(remote);
            carried.add(tuple("back/" + remote.id(), "front/" + local.id()));
        }

        SystemGraph system = assertTimeoutPreemptively(Duration.ofSeconds(10), () -> new Linker().link(
                List.of(graph("front", 9000, frontNodes, List.of()), graph("back", 9001, backNodes, List.of())),
                ZipkinTraces.of(List.of())));

        assertThat(system.flows()).extracting(Flow::from, Flow::to).containsExactlyInAnyOrderElementsOf(carried);
    }

    @Test
    void fieldsAreMatchedFiveTypesDeep() {
        // A response nesting Level0 in Level1 ... in Level7.
        List<Node> frontNodes = new ArrayList<>(List.of(Egress.of("RestClient", "GET", "/levels",
                "http://localhost:9001", null, CodeRef.ofMethod("front.Levels", "get()"),
                new Payload("front.Level7", false))));
        List<Node> backNodes = new ArrayList<>(List.of(Ingress.of("GET", "/levels", CodeRef.ofMethod("back.Levels",
                "get()")).withResponse(new Payload("back.Level7", false))));
        for (int level = 7; level > 0; level--) {
            frontNodes.add(Field.of("front.Level" + level, "inner", "inner", "front.Level" + (level - 1)));
            backNodes.add(Field.of("back.Level" + level, "inner", "inner", "back.Level" + (level - 1)));
        }

        SystemGraph system = new Linker().link(List.of(graph("front", 9000, frontNodes, List.of()),
                graph("back", 9001, backNodes, List.of())), ZipkinTraces.of(List.of()));

        assertThat(system.flows()).extracting(Flow::to).containsExactlyInAnyOrder("front/field:front.Level7.inner",
                "front/field:front.Level6.inner", "front/field:front.Level5.inner", "front/field:front.Level4.inner",
                "front/field:front.Level3.inner", "front/field:front.Level2.inner");
    }

    @Test
    void theLastGraphOfAServiceIsTheOneLinked() {
        ApplicationGraph earlier = graph("back", 9001, List.of(Ingress.of("GET", "/items",
                CodeRef.ofMethod("back.Items", "list()"))), List.of());

        SystemGraph system = new Linker().link(List.of(front, earlier, back), ZipkinTraces.of(List.of()));

        assertThat(system.services()).extracting(ApplicationGraph::service).containsExactly("back", "front");
        assertThat(system.service("back")).hasValue(back);
        assertThat(system.links()).singleElement().extracting(Edge::to).isEqualTo("back/" + ITEM.id());
    }

    @Test
    void aCallWithItsOwnTokenLosesOnlyTheChecksThatAskSomething() {
        Ingress orders = Ingress.of("GET", "/orders", CodeRef.ofMethod("front.Orders", "list()"));
        Egress ownToken = GET_ITEM.withCredentials(Credentials.OAUTH2_CLIENT, "OAuth2ClientHttpRequestInterceptor");
        ApplicationGraph caller = graph("front", 9000, List.of(orders, ownToken),
                List.of(Edge.local(orders.id(), orders.id(), ownToken.id(), 1, List.of())));
        AuthorizationLocation open = new AuthorizationLocation("location:HTTP_REQUEST:back.Config:0:/items/**",
                "authorizeHttpRequests", AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE,
                Requirement.permitAll(), CodeRef.ofClass("back.Config"), null, "/items/**",
                AuthorizationLocation.Denial.THROW, false);
        ApplicationGraph permitted = graph("back", 9001, List.of(ITEM, open),
                List.of(Edge.local(ITEM.id(), ITEM.id(), open.id(), 1, List.of())));
        ApplicationGraph checked = graph("back", 9001, List.of(ITEM, open, ITEM_READ),
                List.of(Edge.local(ITEM.id(), ITEM.id(), open.id(), 1, List.of()),
                        Edge.local(ITEM.id(), open.id(), ITEM_READ.id(), 2, List.of())));

        // Nothing there to lose.
        assertThat(new Linker().link(List.of(caller, permitted), ZipkinTraces.of(List.of())).findings()).isEmpty();
        assertThat(new Linker().link(List.of(caller, checked), ZipkinTraces.of(List.of())).findings())
                .singleElement().satisfies(finding -> {
                    assertThat(finding.kind()).isEqualTo(Finding.Kind.BYPASSED);
                    assertThat(finding.message()).contains("with its own OAuth2 client token"
                            + " (OAuth2ClientHttpRequestInterceptor): the checks there (test) evaluate front");
                });
    }

    @Test
    void aGatewayRouteForAnyMethodReachesEndpointsNotTasksOrSocketSessions() {
        // A route without a Method predicate forwards every method. Nothing calls a scheduled task (decision 0046): its
        // route is no path. A WebSocket session starts with its GET handshake.
        Egress route = Egress.of("Gateway", "*", "/**", "http://back", null, CodeRef.ofClass("application properties"),
                null);
        Ingress purge = Ingress.of("SCHEDULED", "Cleanup.purge", CodeRef.ofMethod("back.Cleanup", "purge()"));
        Ingress session = Ingress.of("WEBSOCKET", "/updates", CodeRef.ofClass("back.Updates"));
        Ingress handshake = Ingress.of("GET", "/updates", CodeRef.ofClass("back.Updates"));
        ApplicationGraph service = graph("back", 9001, List.of(ITEM, purge, session, handshake), List.of());

        SystemGraph system = new Linker().link(List.of(graph("gateway", 9000, List.of(route), List.of()), service),
                ZipkinTraces.of(List.of()));

        assertThat(system.links()).extracting(Edge::to).containsExactlyInAnyOrder("back/" + ITEM.id(),
                "back/" + handshake.id());
    }

    @Test
    void aCallToAnotherPortOfAServiceIsALinkToIt() {
        // The management port: Actuator answers there, the application on the main one.
        Egress health = Egress.of("RestClient", "GET", "/actuator/health", "http://localhost:9091", null,
                CodeRef.ofMethod("front.Health", "check()"), new Payload("front.HealthDto", false));
        Ingress actuator = Ingress.of("GET", "/actuator/health", CodeRef.ofClass("HealthEndpoint"));
        ApplicationGraph caller = graph("front", 9000, List.of(health, Field.of("front.HealthDto", "status", "status",
                "java.lang.String")), List.of());
        ApplicationGraph callee = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "back", "test", 9001,
                AuthoritySource.UNKNOWN, List.of(actuator), List.of(), List.of(), List.of(), List.of(), List.of(9091));

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of()));

        assertThat(system.links()).singleElement().extracting(Edge::to).isEqualTo("back/" + actuator.id());
        // What the endpoint returns isn't known, so none of its fields is matched to the caller's.
        assertThat(system.flows()).isEmpty();
    }

    @Test
    void aHostNameInADomainIsAnAddressMatchedByPort() {
        // A cluster's DNS name, not a service name: the port says which service it is.
        Egress call = Egress.of("RestClient", "GET", "/items/{id}", "http://back.shop.svc.cluster.local:9001", null,
                CodeRef.ofMethod("front.ItemClient", "get(long)"), null);
        Egress elsewhere = Egress.of("RestClient", "GET", "/items/{id}", "https://items.example.com", null,
                CodeRef.ofMethod("front.Partner", "get(long)"), null);

        SystemGraph system = new Linker().link(List.of(graph("front", 9000, List.of(call, elsewhere), List.of()),
                back), ZipkinTraces.of(List.of()));

        assertThat(system.links()).singleElement().satisfies(link -> {
            assertThat(link.from()).isEqualTo("front/" + call.id());
            assertThat(link.to()).isEqualTo("back/" + ITEM.id());
        });
    }

    @Test
    void aCallWithAConstantQueryLinksToTheEndpointItSelects() {
        Egress call = Egress.of("RestClient", "GET", "/user/messages", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Messages", "delegated()"), null).withQuery("use_case=delegation");
        Ingress plain = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "mine()"));
        Ingress delegated = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "delegated()"))
                .andParams("use_case=delegation");
        Ingress impersonated = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages",
                "impersonated()")).andParams("use_case=impersonation");

        SystemGraph system = new Linker().link(List.of(graph("front", 9000, List.of(call), List.of()),
                graph("back", 9001, List.of(plain, delegated, impersonated), List.of())), ZipkinTraces.of(List.of()));

        // The plain mapping takes the query too, but Spring prefers the one whose params it meets.
        assertThat(system.links()).extracting(Edge::to).containsExactly("back/" + delegated.id());
    }

    @Test
    void aHeaderTheTraceDoesNotRecordLeavesTheEndpointOpen() {
        // GET /reports, and with X-API-VERSION: 2 the second version: the request may have sent the header or not.
        Ingress first = Ingress.of("GET", "/reports", CodeRef.ofMethod("back.Reports", "v1()"));
        Ingress second = Ingress.of("GET", "/reports", CodeRef.ofMethod("back.Reports", "v2()"))
                .andParams("header:X-API-VERSION=2");
        AuthorizationLocation anyRequest = location("location:HTTP_REQUEST:back.Config:0:anyRequest",
                AuthorizationLocation.Scope.HTTP_REQUEST, Requirement.authenticated());
        Egress call = Egress.of("RestClient", "GET", "/reports", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Reports", "get()"), null).withQuery("format=pdf");
        ApplicationGraph callee = graph("back", 9001, List.of(first, second, anyRequest),
                List.of(Edge.local(first.id(), first.id(), anyRequest.id(), 1, List.of()),
                        Edge.local(second.id(), second.id(), anyRequest.id(), 1, List.of())));
        List<TraceSpan> trace = List.of(
                span("1", null, "SERVER", "GET /reports", "back", Map.of("http.request.method", "GET",
                        "http.route", "/reports", "url.query", "format=pdf")),
                decision("2", "1", "authorize request", "true", "AuthorizationDecision [granted=true]"));

        SystemGraph system = new Linker().link(List.of(graph("front", 9000, List.of(call), List.of()), callee),
                ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).extracting(Edge::to).containsExactlyInAnyOrder("back/" + first.id(),
                "back/" + second.id());
        assertThat(system.observations()).isEmpty();
    }

    @Test
    void eachTracedCallIsCountedOnceEvenWhenTwoLibrariesSpanIt() {
        // RestClient's observation, and the HTTP client's own span below it, which the request carries.
        List<TraceSpan> twice = List.of(
                span("1", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/items/{id}")),
                span("2", "1", "CLIENT", "GET", "front", Map.of("http.request.method", "GET",
                        "url.full", "http://localhost:9001/items/7")),
                span("3", "2", "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE));
        List<TraceSpan> once = List.of(
                span("11", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/items/{id}")),
                span("12", "11", "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE));

        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(twice, once)));

        assertThat(system.links()).singleElement().extracting(Edge::kind).isEqualTo(Edge.Kind.NETWORK_OBSERVED);
        assertThat(system.observation(Observation.linkSubject("front/" + GET_ITEM.id(), "back/" + ITEM.id())))
                .hasValueSatisfying(observation -> assertThat(observation.count()).isEqualTo(2));
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void servicesThatWereNotScannedAreLeftOutOfTheTraces() {
        // A payment provider traced into the same Zipkin, called by front and calling back.
        List<TraceSpan> trace = List.of(
                span("1", null, "CLIENT", "http post", "front", Map.of("method", "POST", "uri", "/payments")),
                span("2", "1", "SERVER", "http post /payments", "payments", Map.of("method", "POST",
                        "uri", "/payments")),
                span("3", "2", null, "authorize request", "payments", Map.of(
                        "spring.security.authorization.decision", "true",
                        "spring.security.authorization.decision.details", "AuthorizationDecision [granted=true]")),
                span("4", "2", "CLIENT", "http get", "payments", Map.of("method", "GET", "uri", "/items/{id}")),
                span("5", "4", "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE));

        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).singleElement().extracting(Edge::kind).isEqualTo(Edge.Kind.NETWORK_INFERRED);
        assertThat(system.observations()).isEmpty();
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void aCallTheTraceCannotPinToOneEndpointKeepsItsStaticLinks() {
        // Without the query, the trace can't say whether ?use_case=delegation chose the other mapping.
        Egress call = Egress.of("RestClient", "GET", "/user/messages", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Messages", "get()"), null);
        Ingress plain = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "mine()"));
        Ingress delegated = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "delegated()"))
                .andParams("use_case=delegation");
        List<TraceSpan> trace = List.of(
                span("1", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/user/messages")),
                span("2", "1", "SERVER", "http get /user/messages", "back", Map.of("method", "GET",
                        "uri", "/user/messages")));

        ApplicationGraph caller = graph("front", 9000, List.of(call), List.of());
        ApplicationGraph callee = graph("back", 9001, List.of(plain, delegated), List.of());

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).extracting(Edge::to, Edge::kind).containsExactlyInAnyOrder(
                tuple("back/" + plain.id(), Edge.Kind.NETWORK_INFERRED),
                tuple("back/" + delegated.id(), Edge.Kind.NETWORK_INFERRED));
        assertThat(system.observations()).isEmpty();
        assertThat(system.findings()).isEmpty();

        // A call to either that front's graph doesn't make is still one it doesn't make.
        List<TraceSpan> unknown = List.of(
                span("11", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/messages/inbox")),
                span("12", "11", "SERVER", "http get /user/messages", "back", Map.of("method", "GET",
                        "uri", "/user/messages")));
        assertThat(new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of(unknown))).findings())
                .singleElement().extracting(Finding::message).isEqualTo("front called back GET /messages/inbox, which"
                        + " matches no static egress in front");
    }

    @Test
    void aTracedCallToARouteTheCalleeDoesNotServeIsAFinding() {
        Egress stock = Egress.of("RestClient", "GET", "/stock/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Stock", "get(long)"), null);
        // OpenTelemetry's client span: the URL, no route template.
        List<TraceSpan> trace = List.of(
                span("1", null, "CLIENT", "GET", "front", Map.of("http.request.method", "GET",
                        "url.full", "http://localhost:9001/stock/7")),
                span("2", "1", "SERVER", "GET /stock/{id}", "back", Map.of("http.request.method", "GET",
                        "http.route", "/stock/{id}")));

        SystemGraph system = new Linker().link(List.of(graph("front", 9000, List.of(stock), List.of()), back),
                ZipkinTraces.of(List.of(trace)));

        assertThat(system.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.UNMATCHED_CALL);
            assertThat(finding.message()).isEqualTo("front called back GET http://localhost:9001/stock/7, which"
                    + " matches no static ingress in back");
        });
    }

    @Test
    void grpcAndHttpCallsOfOneServiceLinkByTheirOwnKeys() {
        Egress reserveCall = Egress.of("gRPC", "GRPC", "shop.Stock/Reserve", null, "static://localhost:9090",
                CodeRef.ofMethod("front.Stock", "reserve()"), null);
        Egress releaseCall = Egress.of("gRPC", "GRPC", "shop.Stock/Release", null, "static://localhost:9090",
                CodeRef.ofMethod("front.Stock", "release()"), null);
        Ingress reserve = Ingress.of("GRPC", "shop.Stock/Reserve", CodeRef.ofMethod("back.Stock", "reserve()"));
        ApplicationGraph caller = graph("front", 9000, List.of(GET_ITEM, reserveCall, releaseCall), List.of());
        ApplicationGraph callee = graph("back", 9001, List.of(ITEM, reserve), List.of());
        Map<String, String> grpc = Map.of("rpc.system", "grpc", "rpc.service", "shop.Stock", "rpc.method", "Reserve");
        List<TraceSpan> rpc = List.of(span("1", null, "CLIENT", "shop.stock/reserve", "front", grpc),
                span("2", "1", "SERVER", "shop.stock/reserve", "back", grpc));
        // An HTTP call whose span names an rpc too, of the http system: matched by its method and route.
        Map<String, String> http = Map.of("rpc.system", "http", "rpc.service", "Items", "rpc.method", "get",
                "method", "GET", "uri", "/items/{itemId}");
        List<TraceSpan> get = List.of(span("11", null, "CLIENT", "http get", "front", http),
                span("12", "11", "SERVER", "http get /items/{itemId}", "back", http));

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of(rpc, get)));

        assertThat(system.links()).extracting(Edge::from, Edge::to, Edge::kind).containsExactlyInAnyOrder(
                tuple("front/" + reserveCall.id(), "back/" + reserve.id(), Edge.Kind.NETWORK_OBSERVED),
                tuple("front/" + GET_ITEM.id(), "back/" + ITEM.id(), Edge.Kind.NETWORK_OBSERVED));
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void aCallIsTheOneOnThePathOfTheRequestItWasMadeFor() {
        // Two endpoints of front call GET /items/{id}, each through its own client method.
        Ingress orders = Ingress.of("GET", "/orders", CodeRef.ofMethod("front.Orders", "list()"));
        Ingress basket = Ingress.of("GET", "/basket", CodeRef.ofMethod("front.Basket", "get()"));
        Ingress reorder = Ingress.of("POST", "/reorder", CodeRef.ofMethod("front.Reorder", "post()"));
        Egress forOrders = Egress.of("RestClient", "GET", "/items/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("front.OrderItems", "get(long)"), null);
        Egress forBasket = Egress.of("RestClient", "GET", "/items/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("front.BasketItems", "get(long)"), null);
        ApplicationGraph caller = graph("front", 9000, List.of(orders, basket, reorder, forOrders, forBasket),
                List.of(Edge.local(orders.id(), orders.id(), forOrders.id(), 1, List.of()),
                        Edge.local(basket.id(), basket.id(), forBasket.id(), 1, List.of())));
        List<TraceSpan> fromOrders = List.of(
                span("1", null, "SERVER", "http get /orders", "front", Map.of("method", "GET", "uri", "/orders")),
                span("2", "1", null, "load items", "front", Map.of()),
                span("3", "2", "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/items/{id}")),
                span("4", "3", "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE));

        assertThat(new Linker().link(List.of(caller, back), ZipkinTraces.of(List.of(fromOrders))).links())
                .extracting(Edge::from, Edge::kind).containsExactlyInAnyOrder(
                        tuple("front/" + forOrders.id(), Edge.Kind.NETWORK_OBSERVED),
                        tuple("front/" + forBasket.id(), Edge.Kind.NETWORK_INFERRED));

        // A request whose endpoint the trace doesn't name, one whose static path shows neither call, and a call made
        // outside any request: either call could have been it.
        List<TraceSpan> unnamed = List.of(
                span("11", null, "SERVER", "http get", "front", Map.of("method", "GET")),
                span("12", "11", "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/items/{id}")),
                span("13", "12", "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE));
        List<TraceSpan> unseen = List.of(
                span("21", null, "SERVER", "http post /reorder", "front", Map.of("method", "POST", "uri", "/reorder")),
                span("22", "21", "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/items/{id}")),
                span("23", "22", "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE));
        List<TraceSpan> unserved = List.of(
                span("31", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/items/{id}")),
                span("32", "31", "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE));
        for (List<TraceSpan> trace : List.of(unnamed, unseen, unserved)) {
            assertThat(new Linker().link(List.of(caller, back), ZipkinTraces.of(List.of(trace))).links())
                    .extracting(Edge::kind).containsOnly(Edge.Kind.NETWORK_OBSERVED).hasSize(2);
        }
    }

    @Test
    void aGraphQlCallIsTheOperationOfTheTypeTheServerRan() {
        // A query and a mutation may share a root field's name; the operation's type tells them apart.
        Egress read = Egress.of("GraphQlClient", "QUERY", "person", "http://localhost:9001", null,
                CodeRef.ofMethod("front.People", "get()"), null);
        Egress rename = Egress.of("GraphQlClient", "MUTATION", "person", "http://localhost:9001", null,
                CodeRef.ofMethod("front.People", "rename()"), null);
        Egress everyone = Egress.of("GraphQlClient", "QUERY", "everyone", "http://localhost:9001", null,
                CodeRef.ofMethod("front.People", "list()"), null);
        Egress raw = Egress.of("RestClient", "POST", "/graphql", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Raw", "post()"), null);
        Ingress query = Ingress.of("QUERY", "person", CodeRef.ofMethod("back.People", "person()"));
        Ingress mutation = Ingress.of("MUTATION", "person", CodeRef.ofMethod("back.People", "rename()"));
        List<TraceSpan> trace = List.of(
                span("1", null, "CLIENT", "http post", "front", Map.of("method", "POST",
                        "http.url", "http://localhost:9001/graphql", "uri", "none")),
                span("2", "1", "SERVER", "http post /graphql", "back", Map.of("method", "POST", "uri", "/graphql")),
                span("3", "2", null, "graphql mutation", "back", Map.of("graphql.operation.type", "mutation")),
                span("4", "3", null, "graphql field person", "back", Map.of("graphql.field.path", "/person")),
                // A field of the result, not an operation.
                span("5", "4", null, "graphql field name", "back", Map.of("graphql.field.path", "/person/name")));

        SystemGraph system = new Linker().link(List.of(graph("front", 9000, List.of(read, rename, everyone, raw),
                List.of()), graph("back", 9001, List.of(query, mutation), List.of())), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).extracting(Edge::from, Edge::to, Edge::kind).containsExactlyInAnyOrder(
                tuple("front/" + read.id(), "back/" + query.id(), Edge.Kind.NETWORK_INFERRED),
                tuple("front/" + rename.id(), "back/" + mutation.id(), Edge.Kind.NETWORK_OBSERVED));
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void aServerSpanThatRecordsItsQueryPicksTheEndpoint() {
        Ingress plain = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "mine()"));
        Ingress delegated = Ingress.of("GET", "/user/messages", CodeRef.ofMethod("back.Messages", "delegated()"))
                .andParams("use_case=delegation");
        AuthorizationLocation mine = location("location:METHOD:back.Messages#mine", AuthorizationLocation.Scope.METHOD,
                Requirement.anyAuthority(List.of("SCOPE_messages")).withSource("hasAuthority('SCOPE_messages')"));
        AuthorizationLocation delegation = location("location:METHOD:back.Messages#delegated",
                AuthorizationLocation.Scope.METHOD, Requirement.anyAuthority(List.of("SCOPE_delegate"))
                        .withSource("hasAuthority('SCOPE_delegate')"));
        ApplicationGraph callee = graph("back", 9001, List.of(plain, delegated, mine, delegation),
                List.of(Edge.local(plain.id(), plain.id(), mine.id(), 1, List.of()),
                        Edge.local(delegated.id(), delegated.id(), delegation.id(), 1, List.of())));
        Ingress inbox = Ingress.of("GET", "/inbox", CodeRef.ofMethod("front.Inbox", "get()"));
        Egress call = Egress.of("RestClient", "GET", "/user/messages", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Messages", "get()"), null);
        AuthorizationLocation signedIn = location("location:HTTP_REQUEST:front.Config:0:anyRequest",
                AuthorizationLocation.Scope.HTTP_REQUEST, Requirement.authenticated());
        ApplicationGraph caller = graph("front", 9000, List.of(inbox, call, signedIn),
                List.of(Edge.local(inbox.id(), inbox.id(), signedIn.id(), 1, List.of())));
        String granted = "ExpressionAuthorizationDecision [granted=true,"
                + " expressionAttribute=hasAuthority('SCOPE_delegate')]";
        // OpenTelemetry's url.query, and the target of its versions before.
        List<TraceSpan> current = List.of(
                span("1", null, "SERVER", "GET /user/messages", "back", Map.of("http.request.method", "GET",
                        "http.route", "/user/messages", "url.query", "use_case=delegation")),
                decision("2", "1", "authorize method", "true", granted));
        List<TraceSpan> older = List.of(
                span("11", null, "SERVER", "GET /user/messages", "back", Map.of("http.method", "GET",
                        "http.route", "/user/messages", "http.target", "/user/messages?use_case=delegation")),
                decision("12", "11", "authorize method", "true", granted));
        // The caller's URL, up to its fragment.
        List<TraceSpan> called = List.of(
                span("21", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/user/messages",
                        "http.url", "http://localhost:9001/user/messages?use_case=delegation#latest")),
                span("22", "21", "SERVER", "http get /user/messages", "back", Map.of("method", "GET",
                        "uri", "/user/messages")),
                decision("23", "22", "authorize method", "true", granted));
        // Called through a client the tracer doesn't instrument, inside a traced method: the query is unknown, and
        // what back checked isn't front's.
        List<TraceSpan> untraced = List.of(
                span("31", null, "SERVER", "http get /inbox", "front", Map.of("method", "GET", "uri", "/inbox")),
                span("32", "31", null, "inbox.load", "front", Map.of()),
                span("33", "32", "SERVER", "http get /user/messages", "back", Map.of("method", "GET",
                        "uri", "/user/messages")),
                decision("34", "33", "authorize method", "true", granted));

        SystemGraph system = new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of(current, older,
                called, untraced)));

        assertThat(system.observation("back/" + delegation.id())).hasValueSatisfying(observation ->
                assertThat(observation.granted()).isEqualTo(3));
        assertThat(system.observation("back/" + mine.id())).isEmpty();
        assertThat(system.observation("front/" + signedIn.id())).isEmpty();
        assertThat(system.links()).filteredOn(link -> link.kind() == Edge.Kind.NETWORK_OBSERVED).singleElement()
                .extracting(Edge::to).isEqualTo("back/" + delegated.id());
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void endpointsToldApartByWhatTheTraceDoesNotRecordAreNotCredited() {
        // Versioned by a header the trace doesn't record: the query meets both.
        Ingress first = Ingress.of("GET", "/reports", CodeRef.ofMethod("back.Reports", "v1()"))
                .andParams("header:X-API-VERSION=1");
        Ingress second = Ingress.of("GET", "/reports", CodeRef.ofMethod("back.Reports", "v2()"))
                .andParams("header:X-API-VERSION=2");
        AuthorizationLocation anyRequest = location("location:HTTP_REQUEST:back.Config:0:anyRequest",
                AuthorizationLocation.Scope.HTTP_REQUEST, Requirement.authenticated());
        ApplicationGraph callee = graph("back", 9001, List.of(first, second, anyRequest),
                List.of(Edge.local(first.id(), first.id(), anyRequest.id(), 1, List.of()),
                        Edge.local(second.id(), second.id(), anyRequest.id(), 1, List.of())));
        List<TraceSpan> trace = List.of(
                span("1", null, "SERVER", "GET /reports", "back", Map.of("http.request.method", "GET",
                        "http.route", "/reports", "url.query", "format=pdf")),
                decision("2", "1", "authorize request", "true", "AuthorizationDecision [granted=true]"));

        SystemGraph system = new Linker().link(List.of(callee), ZipkinTraces.of(List.of(trace)));

        assertThat(system.observations()).isEmpty();
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void theRouteOfEveryPathNamesNoEndpoint() {
        // Spring's resource handler's pattern: the URL path says which endpoint it was.
        List<TraceSpan> trace = List.of(
                span("2", null, "CLIENT", "http get", "front", Map.of("method", "GET", "uri", "/items/{id}")),
                span("3", "2", "SERVER", "http get /**", "back", Map.of("method", "GET", "uri", "/**",
                        "http.url", "/items/7")));

        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).singleElement().extracting(Edge::kind).isEqualTo(Edge.Kind.NETWORK_OBSERVED);
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void aFieldCheckIsCountedForEveryElementItGuards() {
        AuthorizationLocation price = new AuthorizationLocation("location:FIELD:back.Item#getPrice()", "@PreAuthorize",
                AuthorizationLocation.Scope.FIELD, AuthorizationLocation.Phase.PRE,
                Requirement.anyAuthority(List.of("ROLE_ADMIN")).withSource("hasRole('ADMIN')"),
                CodeRef.ofMethod("back.Item", "getPrice()"), "price", null, AuthorizationLocation.Denial.THROW, true);
        Ingress items = Ingress.of("GET", "/items", CodeRef.ofMethod("back.Items", "list()"))
                .withResponse(new Payload("back.Item", true));
        ApplicationGraph callee = graph("back", 9001, List.of(items, price),
                List.of(Edge.local(items.id(), items.id(), price.id(), 1, List.of())));
        String details = "ExpressionAuthorizationDecision [granted=%s, expressionAttribute=hasRole('ADMIN')]";
        List<TraceSpan> trace = List.of(
                span("1", null, "SERVER", "http get /items", "back", Map.of("method", "GET", "uri", "/items")),
                decision("2", "1", "authorize method", "true", details.formatted(true)),
                decision("3", "1", "authorize method", "false", details.formatted(false)));

        SystemGraph system = new Linker().link(List.of(callee), ZipkinTraces.of(List.of(trace)));

        assertThat(system.observation("back/" + price.id())).hasValueSatisfying(observation -> {
            assertThat(observation.count()).isEqualTo(2);
            assertThat(observation.granted()).isEqualTo(1);
            assertThat(observation.denied()).isEqualTo(1);
        });
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void aDecisionMatchesOnlyALocationThatChecksWhatItSays() {
        // @Secured("SCOPE_items.read"): an authority check, read without an expression.
        AuthorizationLocation secured = location("location:METHOD:back.Items#get:@Secured",
                AuthorizationLocation.Scope.METHOD, Requirement.anyAuthority(List.of("SCOPE_items.read")));
        ApplicationGraph callee = graph("back", 9001, List.of(ITEM, secured),
                List.of(Edge.local(ITEM.id(), ITEM.id(), secured.id(), 1, List.of())));
        List<TraceSpan> trace = List.of(
                span("3", null, "SERVER", "http get /items/{itemId}", "back", ITEM_ROUTE),
                // An expression the scan didn't see, and a custom manager's decision that names nothing.
                decision("4", "3", "authorize method", "true", "ExpressionAuthorizationDecision [granted=true,"
                        + " expressionAttribute=hasAuthority('SCOPE_items.read')]"),
                decision("5", "3", "authorize method", "true", "AuthorizationDecision [granted=true]"),
                // @Secured's own decision.
                decision("6", "3", "authorize method", "true",
                        "AuthorityAuthorizationDecision [granted=true, authorities=[SCOPE_items.read]]"));

        SystemGraph system = new Linker().link(List.of(callee), ZipkinTraces.of(List.of(trace)));

        assertThat(system.observation("back/" + secured.id())).hasValueSatisfying(observation ->
                assertThat(observation.count()).isEqualTo(1));
        assertThat(system.findings()).extracting(Finding::kind).containsExactly(Finding.Kind.RUNTIME_ONLY_CHECK,
                Finding.Kind.RUNTIME_ONLY_CHECK);
    }

    private static final Egress SEND_ORDER = Egress.of("KafkaTemplate", "KAFKA", "orders", null, null,
            CodeRef.ofMethod("front.Orders", "place(front.Order)"), null);
    private static final Egress SEND_AUDIT = Egress.of("RabbitTemplate", "RABBIT", "audit", null, null,
            CodeRef.ofMethod("front.Audit", "record(java.lang.String)"), null);
    private static final Ingress PLACE = Ingress.of("POST", "/orders", CodeRef.ofMethod("front.Orders", "place()"));
    private static final Ingress ON_ORDER = Ingress.of("KAFKA", "orders", CodeRef.ofMethod("back.Fulfilment",
            "onOrder(back.Order)"));
    private static final Ingress ON_AUDIT = Ingress.of("RABBIT", "audit", CodeRef.ofMethod("back.AuditLog",
            "record(java.lang.String)"));
    private static final AuthorizationLocation SHIP = location("location:METHOD:back.Fulfilment#ship:@PreAuthorize",
            AuthorizationLocation.Scope.METHOD, Requirement.anyAuthority(List.of("ROLE_WAREHOUSE"))
                    .withSource("hasRole('WAREHOUSE')"));

    private final ApplicationGraph producer = graph("front", 9000, List.of(PLACE, SEND_ORDER, SEND_AUDIT),
            List.of(Edge.local(PLACE.id(), PLACE.id(), SEND_ORDER.id(), 1, List.of()),
                    Edge.local(PLACE.id(), SEND_ORDER.id(), SEND_AUDIT.id(), 2, List.of())));
    private final ApplicationGraph consumer = graph("back", 9001, List.of(ON_ORDER, ON_AUDIT, SHIP),
            List.of(Edge.local(ON_ORDER.id(), ON_ORDER.id(), SHIP.id(), 1, List.of())));

    /**
     * Spring Kafka's spans (Spring Boot 4.1.1, observations on): the send a producer span, the delivery a consumer
     * span under it; Spring AMQP's through the default exchange, which routes by queue name.
     */
    @Test
    void tracedMessagesConfirmTheirLinks() {
        List<TraceSpan> trace = List.of(
                span("1", null, "SERVER", "http post /orders", "front", Map.of("method", "POST", "uri", "/orders")),
                span("2", "1", "PRODUCER", "orders send", "front", Map.of("messaging.system", "kafka",
                        "messaging.destination.name", "orders", "messaging.operation", "publish")),
                span("3", "2", "CONSUMER", "orders process", "back", Map.of("messaging.system", "kafka",
                        "messaging.source.name", "orders", "messaging.operation", "process")),
                decision("4", "3", "authorize method", "false",
                        "ExpressionAuthorizationDecision [granted=false, expressionAttribute=hasRole('WAREHOUSE')]"),
                span("5", "1", "PRODUCER", "/audit send", "front", Map.of("messaging.destination.name", "",
                        "messaging.rabbitmq.destination.routing_key", "audit", "spring.rabbit.template.name",
                        "rabbitTemplate")),
                span("6", "5", "CONSUMER", "audit receive", "back", Map.of("messaging.destination.name", "audit",
                        "spring.rabbit.listener.id", "listener#0")));

        SystemGraph system = new Linker().link(List.of(producer, consumer), ZipkinTraces.of(List.of(trace)));

        assertThat(system.links()).extracting(Edge::from, Edge::to, Edge::kind).containsExactlyInAnyOrder(
                tuple("front/" + SEND_ORDER.id(), "back/" + ON_ORDER.id(), Edge.Kind.NETWORK_OBSERVED),
                tuple("front/" + SEND_AUDIT.id(), "back/" + ON_AUDIT.id(), Edge.Kind.NETWORK_OBSERVED));
        assertThat(system.observation(Observation.linkSubject("front/" + SEND_ORDER.id(), "back/" + ON_ORDER.id())))
                .hasValueSatisfying(observation -> assertThat(observation.count()).isEqualTo(1));
        // The listener's check counts for the listener, not for the request that sent the message.
        assertThat(system.observation("back/" + SHIP.id())).hasValueSatisfying(observation ->
                assertThat(observation.denied()).isEqualTo(1));
        assertThat(system.findings()).isEmpty();
        assertThat(system.identities()).isEmpty();
    }

    /**
     * Spring JMS's spans (7.0.9, with Micrometer 1.17.1's jakarta9 conventions): {@code <destination> publish} and,
     * under it, {@code <destination> process}, tagged with the destination and whether it is temporary but not with
     * the broker.
     */
    @Test
    void tracedJmsMessagesConfirmTheirLinks() {
        Egress close = Egress.of("JmsTemplate", "JMS", "ledger.closed", null, null,
                CodeRef.ofMethod("front.Ledger", "close()"), null);
        Ingress onClose = Ingress.of("JMS", "ledger.closed", CodeRef.ofMethod("back.Books", "closed(back.Closed)"));
        ApplicationGraph front = graph("front", 9000, List.of(PLACE, close),
                List.of(Edge.local(PLACE.id(), PLACE.id(), close.id(), 1, List.of())));
        ApplicationGraph back = graph("back", 9001, List.of(onClose), List.of());
        List<TraceSpan> trace = List.of(
                span("1", null, "SERVER", "http post /orders", "front", Map.of("method", "POST", "uri", "/orders")),
                span("2", "1", "PRODUCER", "ledger.closed publish", "front", jms("publish", "ledger.closed")),
                span("3", "2", "CONSUMER", "ledger.closed process", "back", jms("process", "ledger.closed")));
        // A destination Micrometer couldn't name.
        List<TraceSpan> unnamed = List.of(
                span("11", null, "PRODUCER", "unknown publish", "front", jms("publish", "unknown")),
                span("12", "11", "CONSUMER", "unknown process", "back", jms("process", "unknown")));

        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of(trace, unnamed)));

        assertThat(system.links()).extracting(Edge::from, Edge::to, Edge::kind).containsExactly(
                tuple("front/" + close.id(), "back/" + onClose.id(), Edge.Kind.NETWORK_OBSERVED));
        assertThat(system.findings()).extracting(Finding::kind, Finding::message).containsExactly(
                tuple(Finding.Kind.UNMATCHED_CALL, "front sent back a JMS message on ?, which matches no static"
                        + " egress in front"));
    }

    private static Map<String, String> jms(String operation, String destination) {
        return Map.of("messaging.operation", operation, "messaging.destination.name", destination,
                "messaging.destination.temporary", "false", "messaging.message.id", "ID:1",
                "messaging.message.conversation_id", "unknown", "exception", "none");
    }

    @Test
    void aTracedMessageNoStaticSendOrListenerMatchesIsAFinding() {
        List<TraceSpan> unsent = List.of(
                span("1", null, "PRODUCER", "returns send", "front", Map.of("messaging.system", "kafka",
                        "messaging.destination.name", "returns")),
                span("2", "1", "CONSUMER", "returns process", "back", Map.of("messaging.system", "kafka",
                        "messaging.source.name", "returns")));
        // A named exchange: its bindings, not the trace, say which queue gets the message.
        List<TraceSpan> exchanged = List.of(
                span("11", null, "PRODUCER", "events/audit send", "front", Map.of("messaging.destination.name",
                        "events", "messaging.rabbitmq.destination.routing_key", "audit")),
                span("12", "11", "CONSUMER", "audit receive", "back", Map.of("messaging.destination.name", "audit",
                        "spring.rabbit.listener.id", "listener#0")));
        List<TraceSpan> unheard = List.of(
                span("21", null, "PRODUCER", "orders send", "front", Map.of("messaging.system", "kafka",
                        "messaging.destination.name", "orders")),
                span("22", "21", "CONSUMER", "orders process", "elsewhere", Map.of("messaging.system", "kafka",
                        "messaging.source.name", "orders")));
        ApplicationGraph quiet = graph("back", 9001, List.of(ON_AUDIT), List.of());
        ApplicationGraph elsewhere = graph("elsewhere", 9002, List.of(ON_AUDIT), List.of());

        SystemGraph system = new Linker().link(List.of(producer, quiet, elsewhere),
                ZipkinTraces.of(List.of(unsent, exchanged, unheard)));

        assertThat(system.findings()).extracting(Finding::kind, Finding::message).containsExactlyInAnyOrder(
                tuple(Finding.Kind.UNMATCHED_CALL, "front sent back a KAFKA message on returns, which matches no"
                        + " static egress in front"),
                tuple(Finding.Kind.UNMATCHED_CALL, "front sent back a RABBIT message on audit, which matches no"
                        + " static egress in front"),
                tuple(Finding.Kind.UNMATCHED_CALL, "front sent elsewhere a KAFKA message on orders, which matches"
                        + " no static listener in elsewhere"));
    }

    @Test
    void aDecisionThatAsksForNoAuthoritiesNamesNone() {
        assertThat(Linker.askedAuthorities("AuthorityAuthorizationDecision [granted=false, authorities=[]]")).isEmpty();
        assertThat(Linker.askedAuthorities("AuthorityAuthorizationDecision [granted=true, authorities=[ROLE_A,"
                + " ROLE_B]]")).containsExactly("ROLE_A", "ROLE_B");
    }

    private static ApplicationGraph graph(String service, int port, List<Node> nodes, List<Edge> edges) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "test", port, AuthoritySource.UNKNOWN,
                new ArrayList<>(nodes), edges, List.of(), List.of(), List.of());
    }

    private static AuthorizationLocation location(String id, AuthorizationLocation.Scope scope,
            Requirement requirement) {
        return new AuthorizationLocation(id, "test", scope, AuthorizationLocation.Phase.PRE, requirement,
                CodeRef.ofClass("back.Items"), null, null, AuthorizationLocation.Denial.THROW, false);
    }

    private static TraceSpan span(String id, String parent, String kind, String name, String service,
            Map<String, String> tags) {
        return new TraceSpan("t", id, parent, kind, name, service, Long.parseLong(id), tags);
    }

    private static TraceSpan decision(String id, String parent, String name, String granted, String details) {
        return span(id, parent, null, name, "back", Map.of("spring.security.authorization.decision", granted,
                "spring.security.authorization.decision.details", details));
    }

    /**
     * A decision for a JWT caller holding {@code authorities}, as Spring's {@code toString} of them.
     */
    private static TraceSpan identified(String id, String parent, String name, String granted, String details,
            String authorities) {
        return span(id, parent, null, name, "back", Map.of("spring.security.authorization.decision", granted,
                "spring.security.authorization.decision.details", details,
                "spring.security.authentication.type", "JwtAuthenticationToken",
                "spring.security.authentication.authorities", authorities));
    }
}
