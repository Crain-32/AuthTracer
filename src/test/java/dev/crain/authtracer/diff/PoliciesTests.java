package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import dev.crain.authtracer.diff.DiffReport.Kind;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.diff.TestGraphs.FieldCheck;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;

class PoliciesTests {

    private static final Requirement AUTHENTICATED = Requirement.authenticated();
    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"));
    private static final ProvidedFact PCI_ADMIN_ONLY = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI",
            List.of("PCI"), "hasRole('ADMIN')", "card data", ProvidedFact.Origin.ORG);

    @Test
    void aLabelledFieldMustRequireAtLeastItsPolicy() {
        ApplicationGraph graph = governed(TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"),
                        List.of(new FieldCheck("iban", ADMIN)))
                .endpoint("GET", "/cards/{id}", List.of(AUTHENTICATED), List.of("iban"), List.of())
                .build("head"));

        List<Exposure> exposures = Exposures.of(graph);

        assertThat(exposures).filteredOn(exposure -> !exposure.violations().isEmpty())
                .singleElement().satisfies(exposure -> {
                    // The admin-only field check satisfies the policy on /accounts; /cards has no field check.
                    assertThat(exposure.endpoint()).isEqualTo("GET /cards/{id}");
                    assertThat(exposure.field()).isEqualTo("iban");
                    assertThat(exposure.violations()).singleElement().satisfies(violation -> {
                        assertThat(violation.label()).isEqualTo("PCI");
                        assertThat(violation.requires()).isEqualTo("ROLE_ADMIN");
                        assertThat(violation.reason()).isEqualTo("card data");
                    });
                });
    }

    @Test
    void theDiffFailsOnANewViolationOnly() {
        ApplicationGraph base = governed(TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("iban"),
                        List.of(new FieldCheck("iban", ADMIN)))
                .build("base"));
        ApplicationGraph head = governed(TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("iban"), List.of())
                .build("head"));

        DiffReport report = GraphDiff.compare(base, head);

        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.POLICY_VIOLATION)
                .singleElement().satisfies(change -> {
                    assertThat(change.field()).isEqualTo("iban");
                    assertThat(change.before()).isEqualTo("ROLE_ADMIN");
                    assertThat(change.after()).isEqualTo("authenticated");
                    assertThat(change.message()).isEqualTo("the PCI policy requires ROLE_ADMIN (card data)");
                });
        assertThat(report.failed(false)).isTrue();
        // An existing violation is not the change's doing.
        assertThat(GraphDiff.compare(head, head).changes()).isEmpty();
    }

    @Test
    void anEndpointPolicyAsksForAnEntryCheckAndALiveOneOnTheChain() {
        ProvidedFact adminFresh = new ProvidedFact(ProvidedFact.Kind.ENDPOINT_POLICY, "PUT /admin/**", List.of(),
                "hasRole('ADMIN')", "revocations", ProvidedFact.Origin.ORG, true);
        // The front checks ROLE_ADMIN from JWT claims and relays the token to a back end that introspects it.
        assertThat(endpointViolations(adminFresh, ADMIN, Credentials.RELAY, AuthoritySource.Freshness.LIVE)).isEmpty();
        // A snapshot downstream can't honor a revocation during the request.
        assertThat(endpointViolations(adminFresh, ADMIN, Credentials.RELAY, AuthoritySource.Freshness.SNAPSHOT))
                .singleElement().satisfies(violation -> {
                    assertThat(violation.label()).isEqualTo("PUT /admin/**");
                    assertThat(violation.requires()).startsWith("ROLE_ADMIN against a live authority source");
                });
        // The back end's check is about the calling service when the token isn't relayed.
        assertThat(endpointViolations(adminFresh, ADMIN, Credentials.OAUTH2_CLIENT, AuthoritySource.Freshness.LIVE))
                .extracting(Policies.Violation::requires).singleElement().asString().contains("live");
        // Without the entry check the policy fails on entry, whatever happens downstream.
        assertThat(endpointViolations(adminFresh, AUTHENTICATED, Credentials.RELAY, AuthoritySource.Freshness.LIVE))
                .extracting(Policies.Violation::requires).containsExactly("ROLE_ADMIN on entry");
    }

    @Test
    void aMethodQualifiedEndpointPolicyCoversAMappingThatAcceptsAnyMethod() {
        ProvidedFact adminOnly = new ProvidedFact(ProvidedFact.Kind.ENDPOINT_POLICY, "PUT /admin/**", List.of(),
                "hasRole('ADMIN')", null, ProvidedFact.Origin.ORG);
        ApplicationGraph graph = withFacts(TestGraphs.service("bank")
                .endpoint("*", "/admin/users", List.of(AUTHENTICATED), List.of(), List.of())
                .endpoint("GET", "/admin/report", List.of(AUTHENTICATED), List.of(), List.of())
                .build("head"), List.of(adminOnly));

        assertThat(Exposures.of(graph)).filteredOn(exposure -> !exposure.violations().isEmpty())
                .extracting(Exposure::endpoint).containsExactly("* /admin/users");
    }

    @Test
    void aServicesOwnPolicyDoesNotReachAnotherServicesOwnData() {
        ProvidedFact local = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI", List.of("PCI"), "hasRole('ADMIN')",
                null, ProvidedFact.Origin.LOCAL);
        ApplicationGraph bank = withFacts(labelled(TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("iban"), List.of())
                .build("head")), List.of(local));
        // The shop labels its own iban; the bank's policy is about the bank's data.
        ApplicationGraph shop = labelled(TestGraphs.service("shop")
                .endpoint("GET", "/cards/{id}", List.of(AUTHENTICATED), List.of("iban"), List.of())
                .build("head"));
        SystemGraph system = new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(bank, shop), List.of(), List.of(),
                List.of(), List.of(), List.of());

        assertThat(Exposures.of(system)).filteredOn(exposure -> !exposure.violations().isEmpty())
                .extracting(Exposure::service).containsExactly("bank");
        // An Org policy applies everywhere.
        SystemGraph governed = new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(bank, withFacts(shop,
                List.of(PCI_ADMIN_ONLY))), List.of(), List.of(), List.of(), List.of(), List.of());
        assertThat(Exposures.of(governed)).filteredOn(exposure -> !exposure.violations().isEmpty())
                .extracting(Exposure::service).containsExactlyInAnyOrder("bank", "shop");
    }

    @Test
    void aServicesOwnPolicyFollowsItsDataIntoTheServicesThatRelayIt() {
        ProvidedFact local = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI", List.of("PCI"), "hasRole('ADMIN')",
                null, ProvidedFact.Origin.LOCAL);
        ApplicationGraph bank = withFacts(labelled(TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(ADMIN), List.of("iban"), List.of())
                .build("head")), List.of(local));
        // The shop returns the bank's iban with only authenticated, relaying the caller's token.
        Ingress cards = Ingress.of("GET", "/cards/{id}", CodeRef.ofMethod("shop.Cards", "get(long)"))
                .withResponse(new Payload("shop.AccountDto", false));
        AuthorizationLocation signedIn = location("location:METHOD:shop.Cards#get", AUTHENTICATED, "shop.Cards");
        Egress call = Egress.of("RestClient", "GET", "/accounts/{id}", "http://bank", null,
                CodeRef.ofMethod("shop.BankClient", "get(long)"), new Payload("shop.AccountDto", false))
                .withCredentials(Credentials.RELAY, "test");
        ApplicationGraph shop = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "shop", "head", 9000,
                AuthoritySource.UNKNOWN, List.of(cards, signedIn, call,
                        Field.of("shop.AccountDto", "iban", "iban", "java.lang.String")),
                List.of(Edge.local(cards.id(), cards.id(), signedIn.id(), 1, List.of()),
                        Edge.local(cards.id(), signedIn.id(), call.id(), 2, List.of())), List.of(), List.of(),
                List.of());
        SystemGraph system = new Linker().link(List.of(bank, shop), ZipkinTraces.of(List.of()));

        // The bank's check counts through the relayed call, so the shop meets the bank's policy...
        assertThat(Exposures.of(system)).allSatisfy(exposure -> assertThat(exposure.violations()).isEmpty());

        // ...until the shop calls with its own token instead.
        ApplicationGraph ownToken = new ApplicationGraph(shop.schemaVersion(), shop.service(), shop.revision(),
                shop.port(), shop.authoritySource(), shop.nodes().stream().map(node -> node instanceof Egress egress
                        ? (Node) egress.withCredentials(Credentials.OAUTH2_CLIENT, "test") : node).toList(),
                shop.edges(), shop.flows(), shop.provided(), shop.findings());
        assertThat(Exposures.of(new Linker().link(List.of(bank, ownToken), ZipkinTraces.of(List.of()))))
                .filteredOn(exposure -> !exposure.violations().isEmpty())
                .singleElement().satisfies(exposure -> {
                    assertThat(exposure.service()).isEqualTo("shop");
                    assertThat(exposure.field()).isEqualTo("iban");
                    assertThat(exposure.violations()).extracting(Policies.Violation::label).containsExactly("PCI");
                });
    }

    @Test
    void aServicesStricterPolicyAddsToTheOrgsForTheSameLabel() {
        ProvidedFact stricter = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI", List.of("PCI"),
                "hasRole('ADMIN') and hasAuthority('SCOPE_cards')", null, ProvidedFact.Origin.LOCAL);
        ApplicationGraph graph = withFacts(labelled(TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(ADMIN), List.of("iban"), List.of())
                .build("head")), List.of(PCI_ADMIN_ONLY, stricter));

        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.field().equals("iban")).singleElement()
                .satisfies(exposure -> assertThat(exposure.violations()).extracting(Policies.Violation::requires)
                        .containsExactly("ROLE_ADMIN and SCOPE_cards"));
    }

    @Test
    void aPolicyIsComparedThroughTheServicesRoleHierarchy() {
        // With ROLE_ADMIN > ROLE_HR the scan widens hasRole('HR') to either role; the policy asks for HR.
        ProvidedFact hrOnly = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI", List.of("PCI"), "hasRole('HR')",
                null, ProvidedFact.Origin.ORG);
        ProvidedFact hrEndpoints = new ProvidedFact(ProvidedFact.Kind.ENDPOINT_POLICY, "GET /accounts/**",
                List.of(), "hasRole('HR')", null, ProvidedFact.Origin.ORG);
        Requirement hr = Requirement.anyAuthority(List.of("ROLE_ADMIN", "ROLE_HR"));
        ApplicationGraph graph = withFacts(labelled(TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(hr), List.of("iban"), List.of())
                .build("head")), List.of(hrOnly, hrEndpoints));
        ApplicationGraph withHierarchy = new ApplicationGraph(graph.schemaVersion(), graph.service(),
                graph.revision(), graph.port(), AuthoritySource.UNKNOWN.withRoleHierarchy(new TreeMap<>(Map.of(
                        "ROLE_ADMIN", new TreeSet<>(Set.of("ROLE_HR"))))), graph.nodes(), graph.edges(),
                graph.flows(), graph.provided(), graph.findings());

        assertThat(Exposures.of(withHierarchy)).allSatisfy(exposure ->
                assertThat(exposure.violations()).isEmpty());
        // Without the hierarchy, a check that also lets ADMIN in asks less than HR.
        assertThat(Exposures.of(graph)).filteredOn(exposure -> !exposure.violations().isEmpty()).isNotEmpty();
    }

    @Test
    void anEndpointPolicyWithoutAMethodCoversEveryMethodOfItsOwnServicesRoutes() {
        ProvidedFact signedIn = new ProvidedFact(ProvidedFact.Kind.ENDPOINT_POLICY, "/admin/**", List.of(),
                "isFullyAuthenticated()", null, ProvidedFact.Origin.LOCAL);
        ApplicationGraph bank = withFacts(TestGraphs.service("bank")
                .endpoint("DELETE", "/admin/users/{id}", List.of(AUTHENTICATED), List.of(), List.of())
                .endpoint("GET", "/admin/report", List.of(Requirement.fullyAuthenticated()), List.of(), List.of())
                // A topic with the same path isn't an HTTP route.
                .endpoint("KAFKA", "/admin/events", List.of(), List.of(), List.of())
                .build("head"), List.of(signedIn));
        // The bank's policy names the bank's routes, not the shop's.
        ApplicationGraph shop = TestGraphs.service("shop")
                .endpoint("GET", "/admin/stock", List.of(AUTHENTICATED), List.of(), List.of()).build("head");
        SystemGraph system = new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(bank, shop), List.of(), List.of(),
                List.of(), List.of(), List.of());

        assertThat(Exposures.of(system)).filteredOn(exposure -> !exposure.violations().isEmpty())
                .singleElement().satisfies(exposure -> {
                    assertThat(exposure.endpoint()).isEqualTo("DELETE /admin/users/{id}");
                    assertThat(exposure.violations()).extracting(Policies.Violation::requires)
                            .containsExactly("fullyAuthenticated on entry");
                });
    }

    @Test
    void anEntryCheckGuardsTheWholeRequestAndTheChainIsReadOnce() {
        ProvidedFact adminOnly = new ProvidedFact(ProvidedFact.Kind.ENDPOINT_POLICY, "PUT /admin/**", List.of(),
                "hasRole('ADMIN')", null, ProvidedFact.Origin.ORG);
        // Front checks ROLE_ADMIN on some branches only, and for one field; it relays the token to back, which calls
        // front's endpoint again.
        Ingress update = Ingress.of("PUT", "/admin/users/{id}", CodeRef.ofMethod("front.Admin", "update(long)"));
        AuthorizationLocation sometimes = location("location:METHOD:front.Admin#update", ADMIN, "front.Admin");
        AuthorizationLocation ssn = new AuthorizationLocation("location:FIELD:front.User#getSsn()", "@PreAuthorize",
                AuthorizationLocation.Scope.FIELD, AuthorizationLocation.Phase.PRE, ADMIN,
                CodeRef.ofMethod("front.User", "getSsn()"), "ssn", null, AuthorizationLocation.Denial.THROW, true);
        Egress toBack = Egress.of("RestClient", "PUT", "/users/{id}", "http://back", null,
                CodeRef.ofMethod("front.Client", "put(long)"), null).withCredentials(Credentials.RELAY, null);
        ApplicationGraph front = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "front", "head", 8080,
                AuthoritySource.UNKNOWN, List.of(update, sometimes, ssn, toBack), List.of(
                        Edge.local(update.id(), update.id(), sometimes.id(), 1, List.of()).asConditional(true),
                        Edge.local(update.id(), update.id(), ssn.id(), 2, List.of()),
                        Edge.local(update.id(), update.id(), toBack.id(), 3, List.of())),
                List.of(), List.of(adminOnly), List.of());
        Ingress users = Ingress.of("PUT", "/users/{id}", CodeRef.ofMethod("back.Users", "put(long)"));
        Egress toFront = Egress.of("RestClient", "PUT", "/admin/users/{id}", "http://front", null,
                CodeRef.ofMethod("back.Callback", "put(long)"), null).withCredentials(Credentials.RELAY, null);
        ApplicationGraph back = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "back", "head", 9000,
                AuthoritySource.UNKNOWN, List.of(users, toFront),
                List.of(Edge.local(users.id(), users.id(), toFront.id(), 1, List.of())), List.of(), List.of(),
                List.of());

        SystemGraph system = new Linker().link(List.of(front, back), ZipkinTraces.of(List.of()));

        assertThat(system.links()).hasSize(2);
        assertThat(Exposures.of(system)).filteredOn(exposure -> !exposure.violations().isEmpty())
                .singleElement().satisfies(exposure -> assertThat(exposure.violations())
                        .extracting(Policies.Violation::requires).containsExactly("ROLE_ADMIN on entry"));
    }

    private static List<Policies.Violation> endpointViolations(ProvidedFact policy, Requirement entry,
            Credentials credentials, AuthoritySource.Freshness backFreshness) {
        Ingress update = Ingress.of("PUT", "/admin/users/{id}", CodeRef.ofMethod("front.Admin", "update(long)"));
        AuthorizationLocation entryCheck = location("location:METHOD:front.Admin#update", entry, "front.Admin");
        Egress call = Egress.of("RestClient", "PUT", "/users/{id}", "http://back", null,
                CodeRef.ofMethod("front.Client", "put(long)"), null).withCredentials(credentials, null);
        ApplicationGraph front = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "front", "head", 8080,
                new AuthoritySource(AuthoritySource.Kind.JWT_CLAIMS, AuthoritySource.Freshness.SNAPSHOT, "jwt", null),
                List.of(update, entryCheck, call), List.of(Edge.local(update.id(), update.id(), entryCheck.id(), 1,
                        List.of()), Edge.local(update.id(), entryCheck.id(), call.id(), 2, List.of())),
                List.of(), List.of(policy), List.of());
        Ingress users = Ingress.of("PUT", "/users/{id}", CodeRef.ofMethod("back.Users", "put(long)"));
        AuthorizationLocation backCheck = location("location:METHOD:back.Users#put", ADMIN, "back.Users");
        ApplicationGraph back = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "back", "head", 9000,
                new AuthoritySource(backFreshness == AuthoritySource.Freshness.LIVE
                        ? AuthoritySource.Kind.OPAQUE_TOKEN_INTROSPECTION : AuthoritySource.Kind.JWT_CLAIMS,
                        backFreshness, "back", null),
                List.of(users, backCheck), List.of(Edge.local(users.id(), users.id(), backCheck.id(), 1, List.of())),
                List.of(), List.of(policy), List.of());
        SystemGraph system = new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(front, back),
                List.of(new Edge("front/" + call.id(), "back/" + users.id(), Edge.Kind.NETWORK_OBSERVED, null, 0,
                        List.of(), true)), List.of(), List.of(), List.of(), List.of());
        return Exposures.of(system).stream().filter(exposure -> exposure.service().equals("front"))
                .flatMap(exposure -> exposure.violations().stream()).toList();
    }

    private static AuthorizationLocation location(String id, Requirement requirement, String className) {
        return new AuthorizationLocation(id, "@PreAuthorize", AuthorizationLocation.Scope.METHOD,
                AuthorizationLocation.Phase.PRE, requirement, CodeRef.ofMethod(className, "m()"), null, null,
                AuthorizationLocation.Denial.THROW, true);
    }

    /**
     * The graph with Account.iban labelled PCI and the PCI policy applied.
     */
    private static ApplicationGraph governed(ApplicationGraph graph) {
        return withFacts(labelled(graph), List.of(PCI_ADMIN_ONLY));
    }

    /**
     * The graph with Account.iban labelled PCI.
     */
    private static ApplicationGraph labelled(ApplicationGraph graph) {
        List<Node> nodes = new ArrayList<>();
        for (Node node : graph.nodes()) {
            nodes.add(node instanceof Field field && field.id().equals(Field.id("app.Account", "iban"))
                    ? field.withLabels(List.of("PCI")) : node);
        }
        return new ApplicationGraph(graph.schemaVersion(), graph.service(), graph.revision(), graph.port(),
                graph.authoritySource(), nodes, graph.edges(), graph.flows(), graph.provided(), graph.findings());
    }

    private static ApplicationGraph withFacts(ApplicationGraph graph, List<ProvidedFact> facts) {
        return new ApplicationGraph(graph.schemaVersion(), graph.service(), graph.revision(), graph.port(),
                graph.authoritySource(), graph.nodes(), graph.edges(), graph.flows(), facts, graph.findings());
    }
}
