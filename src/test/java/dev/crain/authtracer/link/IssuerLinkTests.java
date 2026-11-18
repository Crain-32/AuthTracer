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
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Issuer;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Requirement;
import org.junit.jupiter.api.Test;

/**
 * Decision 0075 (SRC-19): a token carries only scopes a client of the authorization server that signs it can be
 * granted.
 */
class IssuerLinkTests {

    private static final Ingress JWKS = Ingress.of("GET", "/oauth2/jwks", CodeRef.ofClass(
            "org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter"));
    private static final CodeRef DECODER = CodeRef.ofClass("org.springframework.boot.security.oauth2.server.resource"
            + ".autoconfigure.JwtDecoderConfiguration");
    private static final Egress KEYS = Egress.of("JwtDecoder", "GET", "/oauth2/jwks", "http://localhost:9000", null,
            DECODER, null);
    /** A call to the same endpoint that isn't how the service checks its tokens. */
    private static final Egress FETCH = Egress.of("RestClient", "GET", "/oauth2/jwks", "http://localhost:9000", null,
            CodeRef.ofMethod("orders.Keys", "fetch()"), null);
    private static final SortedSet<String> GRANTED = new TreeSet<>(Set.of("FACTOR_BEARER", "ROLE_*",
            "ROLE_ANONYMOUS", "SCOPE_*"));
    private static final AuthoritySource.ClaimAuthorities SCOPES = claim("SCOPE_", "scope", "scp");
    private static final AuthoritySource.ClaimAuthorities ROLES = claim("ROLE_", "roles");
    private static final AuthorizationLocation ADMIN = check("admin", "test", "/admin/**",
            Requirement.anyAuthority(List.of("SCOPE_orders.admin")));
    private static final AuthorizationLocation EXPORT = check("export", "test", null,
            Requirement.anyAuthority(List.of("SCOPE_orders.admin")));
    private static final List<AuthorizationLocation> CHECKS = List.of(
            check("read", "test", "/read/**", Requirement.anyAuthority(List.of("SCOPE_orders.read"))),
            ADMIN,
            EXPORT,
            check("either", "test", "/either/**", Requirement.or(List.of(
                    Requirement.anyAuthority(List.of("SCOPE_orders.admin")),
                    Requirement.anyAuthority(List.of("SCOPE_orders.read"))))),
            check("role", "test", "/role/**", Requirement.anyAuthority(List.of("ROLE_ADMIN"))),
            // An authority no token carries at all is the scan's to report.
            check("permission", "test", "/permission/**", Requirement.anyAuthority(List.of("PERM_EXPORT"))),
            // Enforced outside Spring Security, and judged by its parts.
            check("gateway", "Provided by gateway.yaml", "/gateway/**",
                    Requirement.anyAuthority(List.of("SCOPE_orders.admin"))),
            new AuthorizationLocation("location:SPLIT:orders.Config:split", "test",
                    AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE,
                    Requirement.anyAuthority(List.of("SCOPE_orders.admin")), CodeRef.ofMethod("orders.Config",
                    "split()"), null, "/split/**", AuthorizationLocation.Denial.THROW, false));

    @Test
    void aScopeNoClientOfTheIssuerCanGetDeniesEveryCaller() {
        List<Finding> findings = link(issuer(Map.of("web", Set.of("orders.read"), "batch", Set.of("openid")),
                Set.of()), server("orders", 9001, GRANTED, List.of(KEYS, FETCH), SCOPES, ROLES));
        // A check one of whose ways can pass isn't one.
        assertThat(findings).hasSize(2).allSatisfy(finding -> assertThat(finding.kind())
                .isEqualTo(Finding.Kind.ALWAYS_DENIED));
        assertThat(findings.getFirst().message()).isEqualTo("test on /admin/** in orders asks for SCOPE_orders.admin,"
                + " which no token from auth carries: its clients can be granted only the scopes openid, orders.read,"
                + " so it denies every caller");
        assertThat(findings.getFirst().location()).isEqualTo(ADMIN.target());
        assertThat(findings.get(1).message()).startsWith("test on orders.Config#export() in orders asks for");
    }

    @Test
    void eachResourceServerIsJudgedByTheKeysItFetches() {
        ApplicationGraph auth = issuer(Map.of("web", Set.of("orders.read")), Set.of());
        List<Finding> findings = link(List.of(auth, server("orders", 9001, GRANTED, List.of(KEYS), SCOPES),
                server("billing", 9002, GRANTED, List.of(KEYS), SCOPES)));
        assertThat(findings).extracting(Finding::message).filteredOn(message -> message.contains("/admin/**"))
                .hasSize(2).anyMatch(message -> message.contains(" in orders "))
                .anyMatch(message -> message.contains(" in billing "));
    }

    @Test
    void whatTheIssuerMayAddOrAnotherIssuerMaySignIsNotJudged() {
        ApplicationGraph auth = issuer(Map.of("web", Set.of("orders.read")), Set.of());
        // A client store or customizer AuthTracer can't read may give the scope.
        assertThat(link(issuer(Map.of("web", Set.of("orders.read")), Set.of("the clients JdbcClients stores")),
                server("orders", 9001, GRANTED, List.of(KEYS), SCOPES))).isEmpty();
        // Keys fetched from a server that isn't scanned, or from a scanned one that issues no tokens of its own.
        assertThat(link(auth, server("orders", 9001, GRANTED, List.of(Egress.of("JwtDecoder", "GET", "/keys",
                "http://idp.example.com", null, DECODER, null)), SCOPES))).isEmpty();
        assertThat(link(graph("auth", 9000, null, List.of(JWKS), null), server("orders", 9001, GRANTED,
                List.of(KEYS), SCOPES))).isEmpty();
        // Keys the service holds itself: no server's clients say what its tokens carry.
        assertThat(link(auth, server("orders", 9001, GRANTED, List.of(), SCOPES))).isEmpty();
        // Scopes mapped from a claim AuthTracer can't tell apart from another one's values.
        assertThat(link(auth, server("orders", 9001, GRANTED, List.of(KEYS), SCOPES, claim("SCOPE_", "groups"))))
                .isEmpty();
        assertThat(link(auth, server("orders", 9001, GRANTED, List.of(KEYS), SCOPES, claim("S", "groups"))))
                .isEmpty();
        // No scope claim mapped, or what the tokens grant isn't known.
        assertThat(link(auth, server("orders", 9001, GRANTED, List.of(KEYS), ROLES))).isEmpty();
        assertThat(link(auth, server("orders", 9001, null, List.of(KEYS), SCOPES))).isEmpty();
    }

    @Test
    void anIssuerWithNoScopesGivesNone() {
        assertThat(link(issuer(Map.of("web", Set.of()), Set.of()), server("orders", 9001, GRANTED, List.of(KEYS),
                SCOPES))).extracting(Finding::message)
                .allMatch(message -> message.contains("can be granted only no scopes")).hasSize(4);
    }

    private static List<Finding> link(ApplicationGraph issuer, ApplicationGraph server) {
        return link(List.of(issuer, server));
    }

    private static List<Finding> link(List<ApplicationGraph> services) {
        return new Linker().link(services, ZipkinTraces.of(List.of())).findings().stream()
                .filter(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED).toList();
    }

    private static ApplicationGraph issuer(Map<String, Set<String>> clients, Set<String> unread) {
        TreeMap<String, SortedSet<String>> scopes = new TreeMap<>();
        clients.forEach((client, granted) -> scopes.put(client, new TreeSet<>(granted)));
        return graph("auth", 9000, AuthoritySource.UNKNOWN, List.of(JWKS), new Issuer(scopes, null,
                new TreeSet<>(unread)));
    }

    private static ApplicationGraph server(String service, int port, SortedSet<String> granted, List<Egress> egress,
            AuthoritySource.ClaimAuthorities... claims) {
        AuthoritySource source = new AuthoritySource(AuthoritySource.Kind.JWT_CLAIMS,
                AuthoritySource.Freshness.SNAPSHOT, "jwt", null, granted, new AuthoritySource.Jwt(List.of(claims),
                        null, null, null, null));
        List<Node> nodes = new ArrayList<>(egress);
        nodes.addAll(CHECKS);
        return graph(service, port, source, nodes, null);
    }

    private static ApplicationGraph graph(String service, int port, AuthoritySource source, List<Node> nodes,
            Issuer issuer) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "test", port, source,
                new ArrayList<>(nodes), List.of(), List.of(), List.of(), List.of(), List.of(), issuer);
    }

    private static AuthoritySource.ClaimAuthorities claim(String prefix, String... claims) {
        return new AuthoritySource.ClaimAuthorities(List.of(claims), null, prefix, null);
    }

    private static AuthorizationLocation check(String name, String mechanism, String route, Requirement requirement) {
        return new AuthorizationLocation("location:HTTP_REQUEST:orders.Config:" + name, mechanism,
                AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE, requirement,
                CodeRef.ofMethod("orders.Config", name + "()"), null, route, AuthorizationLocation.Denial.THROW,
                false);
    }
}
