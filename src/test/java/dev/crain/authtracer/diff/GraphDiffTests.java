package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;

import dev.crain.authtracer.diff.DiffReport.Change;
import dev.crain.authtracer.diff.DiffReport.Kind;
import dev.crain.authtracer.diff.DiffReport.Site;
import dev.crain.authtracer.diff.TestGraphs.FieldCheck;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import org.junit.jupiter.api.Test;

class GraphDiffTests {

    private static final Requirement AUTHENTICATED = Requirement.authenticated();
    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"));
    private static final Requirement AUDITOR = Requirement.anyAuthority(List.of("ROLE_AUDITOR"));

    private final ApplicationGraph base = TestGraphs.service("bank")
            .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"),
                    List.of(new FieldCheck("iban", ADMIN)))
            .build("base");

    @Test
    void sameGraphHasNoChanges() {
        DiffReport report = GraphDiff.compare(base, base);
        assertThat(report.changes()).isEmpty();
        assertThat(report.failed(true)).isFalse();
        assertThat(report.markdown()).contains("**Pass**").contains("No authorization changes");
    }

    @Test
    void droppingAFieldCheckWeakensThatFieldOnly() {
        ApplicationGraph head = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"), List.of())
                .build("head");

        DiffReport report = GraphDiff.compare(base, head);

        assertThat(report.changes()).singleElement().satisfies(change -> {
            assertThat(change.kind()).isEqualTo(Kind.WEAKENED);
            assertThat(change.field()).isEqualTo("iban");
            assertThat(change.before()).isEqualTo("ROLE_ADMIN");
            assertThat(change.after()).isEqualTo("authenticated");
        });
        assertThat(report.failed(false)).isTrue();
    }

    @Test
    void changesPointAtTheCheckThatChangedElseTheHandler() {
        ApplicationGraph sideways = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"),
                        List.of(new FieldCheck("iban", AUDITOR)))
                .build("head");
        assertThat(GraphDiff.compare(base, sideways).changes()).singleElement().extracting(Change::site)
                .isEqualTo(new Site("bank", CodeRef.ofMethod("app.Account", "m()"), "@PreAuthorize"));

        // The field check went away: nothing on the path changed, so the endpoint's handler.
        ApplicationGraph dropped = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"), List.of())
                .build("head");
        assertThat(GraphDiff.compare(base, dropped).changes()).singleElement().extracting(Change::site)
                .isEqualTo(Site.of("bank", CodeRef.ofMethod("app.Controller", "/accounts/{id}")));
    }

    @Test
    void sidewaysChangesNeedReview() {
        ApplicationGraph head = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"),
                        List.of(new FieldCheck("iban", AUDITOR)))
                .build("head");

        DiffReport report = GraphDiff.compare(base, head);

        assertThat(report.changes()).extracting(Change::kind).containsExactly(Kind.CHANGED);
        assertThat(report.failed(false)).isFalse();
        assertThat(report.failed(true)).isTrue();
    }

    @Test
    void aNewWeakerRouteToTheSameDataIsADiagonalEscalation() {
        ApplicationGraph head = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"),
                        List.of(new FieldCheck("iban", ADMIN)))
                .endpoint("GET", "/export/{id}", List.of(AUTHENTICATED), List.of("iban"), List.of())
                .build("head");

        DiffReport report = GraphDiff.compare(base, head);

        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.DIAGONAL_ESCALATION)
                .singleElement().satisfies(change -> {
                    assertThat(change.endpoint()).isEqualTo("GET /export/{id}");
                    assertThat(change.field()).isEqualTo("iban");
                    assertThat(change.message()).contains("bank Account.iban").contains("GET /accounts/{id}");
                });
        assertThat(report.changes()).extracting(Change::kind).contains(Kind.NEW_EXPOSURE);
        assertThat(report.failed(false)).isTrue();
    }

    @Test
    void aNewRouteToTheSameDataThatCanNotBeRankedNeedsReview() {
        ApplicationGraph head = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"),
                        List.of(new FieldCheck("iban", ADMIN)))
                .endpoint("GET", "/audit/{id}", List.of(AUDITOR), List.of("iban"), List.of())
                // One asking for more than the existing route is fine.
                .endpoint("GET", "/admin/audit/{id}", List.of(ADMIN, AUDITOR), List.of("iban"), List.of())
                .build("head");

        DiffReport report = GraphDiff.compare(base, head);

        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.CHANGED).singleElement()
                .satisfies(change -> {
                    assertThat(change.endpoint()).isEqualTo("GET /audit/{id}");
                    assertThat(change.before()).isEqualTo("ROLE_ADMIN");
                    assertThat(change.message()).isEqualTo("a new route to bank Account.iban whose requirement"
                            + " can't be ranked against the existing routes");
                });
        // The endpoint itself is new: nothing before it.
        assertThat(report.markdown()).contains("| INFO | NEW_EXPOSURE | bank | `GET /audit/{id}` | (endpoint) |  |"
                + " ROLE_AUDITOR |");
        assertThat(report.failed(false)).isFalse();
    }

    @Test
    void aDiagonalEscalationNamesTheWeakestReadOfTheDataAsItsExample() {
        // Routes to the iban: one asking for more than the others, a search, and two reads, one put more simply.
        TestGraphs routes = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}/audited", List.of(ADMIN, AUDITOR), List.of("iban"), List.of())
                .endpoint("POST", "/accounts/search", List.of(ADMIN), List.of("iban"), List.of())
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED, ADMIN), List.of("iban"), List.of())
                .endpoint("GET", "/cards/{id}", List.of(ADMIN), List.of("iban"), List.of());
        ApplicationGraph before = routes.build("base");
        ApplicationGraph after = routes.endpoint("GET", "/export/{id}", List.of(AUTHENTICATED), List.of("iban"),
                List.of()).build("head");

        assertThat(GraphDiff.compare(before, after).changes())
                .filteredOn(change -> change.kind() == Kind.DIAGONAL_ESCALATION).singleElement()
                .extracting(Change::message).asString().endsWith("(e.g. GET /cards/{id} iban)");
    }

    @Test
    void aChangedRequestRuleIsAtTheRuleWhichIsNoAnnotation() {
        Ingress items = Ingress.of("GET", "/items", CodeRef.ofMethod("app.Items", "list()"));
        DiffReport report = GraphDiff.compare(rule(items, ADMIN), rule(items, AUDITOR));

        assertThat(report.changes()).singleElement().extracting(Change::site)
                .isEqualTo(new Site("bank", CodeRef.ofMethod("app.Security", "chain(HttpSecurity)"), null));
    }

    @Test
    void aViolatedPolicysReasonIsInTheChange() {
        ProvidedFact pci = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI", List.of("PCI"), "hasRole('ADMIN')",
                "card data is for admins", ProvidedFact.Origin.ORG);
        ProvidedFact pii = new ProvidedFact(ProvidedFact.Kind.POLICY, "PII", List.of("PII"), "hasRole('HR')", null,
                ProvidedFact.Origin.ORG);
        ApplicationGraph head = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"), List.of())
                .build("head");
        ApplicationGraph labelled = new ApplicationGraph(head.schemaVersion(), head.service(), head.revision(),
                head.port(), head.authoritySource(), head.nodes().stream().map(node -> node instanceof Field field
                        && field.owner().equals("app.Account") ? field.withLabels(List.of(field.name().equals("iban")
                                ? "PCI" : "PII")) : node).toList(), head.edges(), head.flows(), List.of(pci, pii),
                head.findings());

        assertThat(GraphDiff.compare(base, labelled).changes())
                .filteredOn(change -> change.kind() == Kind.POLICY_VIOLATION).extracting(Change::message)
                .containsExactlyInAnyOrder("the PCI policy requires ROLE_ADMIN (card data is for admins)",
                        "the PII policy requires ROLE_HR");
        // A policy the base broke already isn't this change's doing; a new endpoint that breaks one is.
        assertThat(GraphDiff.compare(labelled, labelled).changes()).isEmpty();
        assertThat(GraphDiff.compare(TestGraphs.service("bank").build("base"), labelled).changes())
                .filteredOn(change -> change.kind() == Kind.POLICY_VIOLATION).extracting(Change::field)
                .containsExactlyInAnyOrder("iban", "owner");
    }

    /**
     * {@code GET /items} behind one request rule.
     */
    private static ApplicationGraph rule(Ingress items, Requirement requirement) {
        AuthorizationLocation rule = new AuthorizationLocation("location:HTTP_REQUEST:app.Security:0:/items",
                "authorizeHttpRequests", AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE,
                requirement, CodeRef.ofMethod("app.Security", "chain(HttpSecurity)"), null, "/items",
                AuthorizationLocation.Denial.THROW, false);
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080, AuthoritySource.UNKNOWN,
                List.of(items, rule), List.of(Edge.local(items.id(), items.id(), rule.id(), 1, List.of())), List.of(),
                List.of(), List.of());
    }

    @Test
    void aNewRouteAsStrongAsAnExistingOneIsFine() {
        ApplicationGraph head = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(AUTHENTICATED), List.of("owner", "iban"),
                        List.of(new FieldCheck("iban", ADMIN)))
                .endpoint("GET", "/admin/export/{id}", List.of(ADMIN), List.of("iban"), List.of())
                .build("head");

        DiffReport report = GraphDiff.compare(base, head);

        assertThat(report.changes()).extracting(Change::kind).doesNotContain(Kind.DIAGONAL_ESCALATION, Kind.WEAKENED);
        assertThat(report.failed(true)).isFalse();
    }

    @Test
    void renamingARouteVariableComparesTheEndpointWithItself() {
        ApplicationGraph before = TestGraphs.service("bank")
                .endpoint("DELETE", "/accounts/{id}", List.of(ADMIN), List.of(), List.of()).build("base");
        ApplicationGraph after = TestGraphs.service("bank")
                .endpoint("DELETE", "/accounts/{accountId}", List.of(AUTHENTICATED), List.of(), List.of())
                .build("head");

        DiffReport report = GraphDiff.compare(before, after);

        assertThat(report.changes()).singleElement().satisfies(change -> {
            assertThat(change.kind()).isEqualTo(Kind.WEAKENED);
            assertThat(change.endpoint()).isEqualTo("DELETE /accounts/{accountId}");
            assertThat(change.before()).isEqualTo("ROLE_ADMIN");
        });
        assertThat(report.failed(false)).isTrue();
    }

    /**
     * A head scan that read nothing would otherwise pass: every endpoint removed is information only.
     */
    @Test
    void aServiceWhoseHeadHasNoEndpointFailsTheCheck() {
        ApplicationGraph empty = new ApplicationGraph(base.schemaVersion(), base.service(), "head", base.port(),
                base.authoritySource(), List.of(), List.of(), List.of(), List.of(), List.of());

        DiffReport report = GraphDiff.compare(base, empty);

        assertThat(report.changes()).filteredOn(change -> change.severity() == DiffReport.Severity.FAIL)
                .singleElement().satisfies(change -> {
                    assertThat(change.endpoint()).isEqualTo("every endpoint");
                    assertThat(change.message()).startsWith("the head's scan found no endpoint");
                });
        assertThat(report.failed(false)).isTrue();
        assertThat(GraphDiff.compare(base, base).failed(false)).isFalse();
    }

    /**
     * Decision 0110: HEAD has an Ingress of its own only while its rules differ from GET's; without one, HEAD runs the
     * GET handler under GET's rules. Found by mutationTest: a twin that went away read as removed.
     */
    @Test
    void aHeadTwinThatComesOrGoesIsComparedWithGet() {
        Requirement admin = Requirement.anyAuthority(List.of("ROLE_ADMIN"));
        ApplicationGraph twinned = TestGraphs.service("bank")
                .endpoint("GET", "/admin/users", List.of(admin), List.of(), List.of())
                .endpoint("HEAD", "/admin/users", List.of(AUTHENTICATED), List.of(), List.of()).build("base");
        ApplicationGraph open = TestGraphs.service("bank")
                .endpoint("GET", "/admin/users", List.of(Requirement.permitAll()), List.of(), List.of())
                .build("head");
        ApplicationGraph guarded = TestGraphs.service("bank")
                .endpoint("GET", "/admin/users", List.of(admin), List.of(), List.of()).build("head");

        assertThat(GraphDiff.compare(twinned, open).changes()).filteredOn(change -> change.endpoint()
                .equals("HEAD /admin/users")).singleElement().satisfies(change -> {
                    assertThat(change.kind()).isEqualTo(DiffReport.Kind.WEAKENED);
                    assertThat(change.message()).isEqualTo("HEAD now runs the GET handler under GET's rules");
                });
        // The twin appears: HEAD asks less than GET did.
        assertThat(GraphDiff.compare(guarded, twinned).changes()).filteredOn(change -> change.endpoint()
                .equals("HEAD /admin/users")).extracting(DiffReport.Change::kind)
                .containsExactly(DiffReport.Kind.WEAKENED);
        // Gone because HEAD now asks what GET asks: nothing changed for HEAD's callers.
        assertThat(GraphDiff.compare(twinned, guarded).changes()).filteredOn(change -> change.endpoint()
                .equals("HEAD /admin/users")).extracting(DiffReport.Change::kind)
                .containsExactly(DiffReport.Kind.STRENGTHENED);
    }

    @Test
    void newFindingsOfTheSystemAndWithoutAPlaceAreChanges() {
        Finding unmatched = new Finding(Finding.Kind.UNMATCHED_CALL, "front called back GET /x, which matches no"
                + " static ingress in back", CodeRef.ofClass("front"));
        Finding nowhere = new Finding(Finding.Kind.OPAQUE_CONFIG, "a RoleHierarchy built at runtime", null);
        ApplicationGraph graph = base;
        ApplicationGraph withFinding = new ApplicationGraph(graph.schemaVersion(), graph.service(), "head",
                graph.port(), graph.authoritySource(), graph.nodes(), graph.edges(), graph.flows(), graph.provided(),
                List.of(nowhere));
        SystemGraph before = SystemGraph.of(base);
        SystemGraph after = new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(withFinding), List.of(), List.of(),
                List.of(), List.of(), List.of(unmatched));

        DiffReport report = GraphDiff.compare(before, after);

        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.NEW_FINDING)
                .extracting(Change::service, Change::endpoint, Change::after, Change::site)
                .containsExactlyInAnyOrder(tuple("bank", "", "OPAQUE_CONFIG", null),
                        tuple(GraphDiff.SYSTEM, "front", "UNMATCHED_CALL", Site.of(GraphDiff.SYSTEM,
                                CodeRef.ofClass("front"))));
        assertThat(GraphDiff.compare(after, after).changes()).isEmpty();
    }

    @Test
    void theMarkdownTableEscapesPipesInEveryCell() {
        Change change = Change.of(Kind.WEAKENED, "bank", "GET /accounts?view=a|b", "iban", "hasRole('A') || x",
                "authenticated", null);

        String row = new DiffReport("base", "head", List.of(change)).markdown().lines()
                .filter(line -> line.startsWith("| FAIL")).findFirst().orElseThrow();

        assertThat(row.replace("\\|", "").chars().filter(c -> c == '|')).hasSize(8);
    }

    @Test
    void strengtheningAndRemovalAreInformational() {
        ApplicationGraph head = TestGraphs.service("bank")
                .endpoint("GET", "/accounts/{id}", List.of(ADMIN), List.of("owner"), List.of())
                .build("head");

        DiffReport report = GraphDiff.compare(base, head);

        assertThat(report.changes()).extracting(Change::kind)
                .containsExactlyInAnyOrder(Kind.STRENGTHENED, Kind.STRENGTHENED, Kind.REMOVED);
        assertThat(report.failed(true)).isFalse();
    }
}
