package dev.crain.authtracer.link;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Issuer;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Registration;
import dev.crain.authtracer.graph.Requirement;
import org.junit.jupiter.api.Test;

/**
 * Decision 0075 amended: a service's own token carries the scopes its client registration asks for, and only those
 * the authorization server can grant its client; the called path's checks are judged by them.
 */
class ClientTokenLinkTests {

    private static final Ingress TOKEN_ENDPOINT = Ingress.of("POST", "/oauth2/token", CodeRef.ofClass(
            "org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter"));
    private static final Egress TOKEN = Egress.of("OAuth2 client", "POST", "/oauth2/token", "http://localhost:9000",
            null, CodeRef.ofClass("org.springframework.security.oauth2.client.registration.ClientRegistration"), null)
            .withCredentials(Credentials.STATIC, "client registration");
    private static final Ingress SYNC = Ingress.of("KAFKA", "orders.changed", CodeRef.ofMethod("payroll.Changes",
            "changed(payroll.Change)"));
    private static final Ingress ORDER = Ingress.of("GET", "/orders/{id}", CodeRef.ofMethod("orders.Orders",
            "get(long)"));
    private static final SortedSet<String> GRANTED = new TreeSet<>(Set.of("FACTOR_BEARER", "ROLE_*",
            "ROLE_ANONYMOUS", "SCOPE_*"));
    private static final AuthorizationLocation READ = check("read", AuthorizationLocation.Scope.HTTP_REQUEST,
            "SCOPE_orders.read");
    private static final AuthorizationLocation WRITE = check("write", AuthorizationLocation.Scope.METHOD,
            "SCOPE_orders.write");
    private static final AuthorizationLocation ADMIN = check("admin", AuthorizationLocation.Scope.METHOD, "ROLE_ADMIN");
    private static final AuthorizationLocation TOTAL = check("total", AuthorizationLocation.Scope.FIELD,
            "SCOPE_orders.audit");

    @Test
    void aTokenThatCarriesWhatThePathAsksForPasses() {
        assertThat(rejected(registration("payroll", "orders.read"), Map.of("payroll", Set.of("orders.read")),
                List.of(READ))).isEmpty();
    }

    @Test
    void aCheckForAScopeTheTokenDoesntCarryDeniesTheCall() {
        List<Finding> findings = rejected(registration("payroll", "orders.read"), Map.of("payroll",
                Set.of("orders.read"), "web", Set.of("orders.read", "orders.write")), List.of(READ, WRITE));
        // Another client of the server can get the scope, so it isn't a check no token passes.
        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.message()).isEqualTo("payroll calls orders GET /orders/{id} with its own token, as"
                    + " client payroll of auth, which carries only the scopes orders.read: @PreAuthorize there asks"
                    + " for SCOPE_orders.write, so the call is denied");
            assertThat(finding.location()).isEqualTo(call(registration("payroll", "orders.read")).callSite());
        });
        // A registration that asks for no scopes gets a token with none.
        assertThat(rejected(registration("payroll"), Map.of("payroll", Set.of("orders.read")), List.of(READ)))
                .singleElement().extracting(Finding::message).asString()
                .contains("which carries no scopes: authorizeHttpRequests there asks for SCOPE_orders.read");
    }

    @Test
    void aScopeTheClientCantBeGrantedRefusesTheTokenRequest() {
        assertThat(rejected(registration("payroll", "orders.read", "orders.write"), Map.of("payroll",
                Set.of("orders.read")), List.of(READ))).singleElement().extracting(Finding::message)
                .isEqualTo("payroll asks for its own token, as client payroll of auth, with the scopes orders.read,"
                        + " orders.write, but auth grants that client only the scopes orders.read: the token request"
                        + " is refused (invalid_scope), so its call to orders GET /orders/{id} fails");
        assertThat(rejected(registration("batch", "orders.read"), Map.of("payroll", Set.of("orders.read")),
                List.of(READ))).singleElement().extracting(Finding::message)
                .isEqualTo("payroll calls orders GET /orders/{id} with its own token, as client batch of auth, which"
                        + " registers no such client: no token is issued, so the call fails");
    }

    @Test
    void whatAuthTracerCantTellIsNotJudged() {
        Map<String, Set<String>> clients = Map.of("payroll", Set.of("orders.read"));
        // A role, which a customizer may add, and a field check, which only hides its field.
        assertThat(rejected(registration("payroll", "orders.read"), clients, List.of(READ, ADMIN, TOTAL))).isEmpty();
        // A server whose clients AuthTracer can't all read.
        assertThat(findings(call(registration("payroll")), issuer(clients, Set.of("the clients JdbcClients store")),
                List.of(READ))).isEmpty();
        // Tokens from a server that isn't scanned, or a registration AuthTracer doesn't read.
        assertThat(rejected(new Registration("payroll", "payroll", "client_credentials", new TreeSet<>(),
                "https://idp.example.com/token", null), clients, List.of(READ))).isEmpty();
        assertThat(findings(call(null), issuer(clients, Set.of()), List.of(READ))).isEmpty();
        assertThat(findings(call(new Registration("payroll", null, null, null, "http://localhost:9000/oauth2/token",
                null)), issuer(clients, Set.of()), List.of(READ))).isEmpty();
        // A relayed token is the caller's, checked as such.
        assertThat(findings(call(registration("payroll")).withCredentials(Credentials.RELAY, "relay"),
                issuer(clients, Set.of()), List.of(READ))).isEmpty();
    }

    @Test
    void aRegistrationKnownByItsIssuerGetsItsTokensThere() {
        Egress discovery = Egress.of("OAuth2 client", "GET", "/.well-known/openid-configuration",
                "http://localhost:9000", null, TOKEN.callSite(), null);
        Ingress configuration = Ingress.of("GET", "/.well-known/openid-configuration", TOKEN_ENDPOINT.handler());
        ApplicationGraph auth = graph("auth", 9000, AuthoritySource.UNKNOWN, List.of(configuration),
                new Issuer(new TreeMap<>(Map.of("payroll", new TreeSet<>(Set.of("orders.read")))), null, null));
        Egress call = call(new Registration("payroll", "payroll", "client_credentials", new TreeSet<>(),
                null, "http://localhost:9000/"));
        assertThat(link(List.of(auth, caller(call, discovery), callee(List.of(READ))))).singleElement()
                .extracting(Finding::message).asString().contains("which carries no scopes");
    }

    private static List<Finding> rejected(Registration registration, Map<String, Set<String>> clients,
            List<AuthorizationLocation> checks) {
        return findings(call(registration), issuer(clients, Set.of()), checks);
    }

    private static List<Finding> findings(Egress call, ApplicationGraph issuer, List<AuthorizationLocation> checks) {
        return link(List.of(issuer, caller(call, TOKEN), callee(checks)));
    }

    private static List<Finding> link(List<ApplicationGraph> graphs) {
        return new Linker().link(graphs, ZipkinTraces.of(List.of())).findings().stream()
                .filter(finding -> finding.kind() == Finding.Kind.TOKEN_REJECTED).toList();
    }

    private static Registration registration(String clientId, String... scopes) {
        return new Registration("payroll", clientId, "client_credentials", new TreeSet<>(List.of(scopes)),
                "http://localhost:9000/oauth2/token", null);
    }

    private static Egress call(Registration registration) {
        return Egress.of("RestClient", "GET", "/orders/{id}", "http://localhost:9002", null,
                CodeRef.ofMethod("payroll.Orders", "order(long)"), null)
                .withCredentials(Credentials.OAUTH2_CLIENT, "client").withRegistration(registration);
    }

    private static ApplicationGraph issuer(Map<String, Set<String>> clients, Set<String> unread) {
        TreeMap<String, SortedSet<String>> scopes = new TreeMap<>();
        clients.forEach((client, granted) -> scopes.put(client, new TreeSet<>(granted)));
        return graph("auth", 9000, AuthoritySource.UNKNOWN, List.of(TOKEN_ENDPOINT), new Issuer(scopes, null,
                new TreeSet<>(unread)));
    }

    private static ApplicationGraph caller(Egress call, Egress tokens) {
        List<Node> nodes = List.of(SYNC, call, tokens);
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "payroll", "test", 9001, null,
                new ArrayList<>(nodes), List.of(Edge.local(SYNC.id(), SYNC.id(), call.id(), 1, List.of())), List.of(),
                List.of(), List.of());
    }

    private static ApplicationGraph callee(List<AuthorizationLocation> checks) {
        AuthoritySource source = new AuthoritySource(AuthoritySource.Kind.JWT_CLAIMS,
                AuthoritySource.Freshness.SNAPSHOT, "jwt", null, GRANTED, new AuthoritySource.Jwt(List.of(
                        new AuthoritySource.ClaimAuthorities(List.of("scope", "scp"), null, "SCOPE_", null),
                        new AuthoritySource.ClaimAuthorities(List.of("roles"), null, "ROLE_", null)), null, null, null,
                        null));
        List<Node> nodes = new ArrayList<>(checks);
        nodes.add(ORDER);
        List<Edge> path = new ArrayList<>();
        for (int i = 0; i < checks.size(); i++) {
            path.add(Edge.local(ORDER.id(), i == 0 ? ORDER.id() : checks.get(i - 1).id(), checks.get(i).id(), i + 1,
                    List.of()));
        }
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "orders", "test", 9002, source, nodes, path,
                List.of(), List.of(), List.of());
    }

    private static ApplicationGraph graph(String service, int port, AuthoritySource source, List<Node> nodes,
            Issuer issuer) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "test", port, source,
                new ArrayList<>(nodes), List.of(), List.of(), List.of(), List.of(), List.of(), issuer);
    }

    private static AuthorizationLocation check(String name, AuthorizationLocation.Scope scope, String authority) {
        String mechanism = switch (scope) {
            case HTTP_REQUEST -> "authorizeHttpRequests";
            case FIELD -> "@PreAuthorize (field)";
            default -> "@PreAuthorize";
        };
        return new AuthorizationLocation("location:" + scope + ":orders.Orders:" + name, mechanism, scope,
                AuthorizationLocation.Phase.PRE, Requirement.anyAuthority(List.of(authority)),
                CodeRef.ofMethod("orders.Orders", name + "()"), scope == AuthorizationLocation.Scope.FIELD ? name
                        : null, scope == AuthorizationLocation.Scope.HTTP_REQUEST ? "/orders/**" : null,
                AuthorizationLocation.Denial.THROW, false);
    }
}
