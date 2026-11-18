package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.Requirement;
import org.junit.jupiter.api.Test;

class ExposuresTests {

    /**
     * {@code GET /accounts/{id}} returns an Account: its getter checks ssn, a resolver checks ssn too, and another
     * resolver checks team.
     */
    private final ApplicationGraph graph = graph();

    @Test
    void everyCheckOnAFieldCounts() {
        assertThat(requirements().get("ssn")).isEqualTo("ROLE_GETTER and ROLE_RESOLVER");
    }

    @Test
    void aCheckOnAFieldGuardsTheFieldsNestedUnderIt() {
        assertThat(requirements().get("team")).isEqualTo("ROLE_TEAMS");
        assertThat(requirements().get("team.name")).isEqualTo("ROLE_TEAMS");
        assertThat(requirements().get("")).isEqualTo("none");
    }

    @Test
    void aTypeNestedTwiceIsExposedAtBothPathsEachWithItsOwnGuards() {
        Ingress ingress = Ingress.of("GET", "/people/{id}", CodeRef.ofMethod("app.Controller", "person()"))
                .withResponse(new Payload("app.Person", false));
        AuthorizationLocation billing = field("location:FIELD:billing", "ROLE_BILLING", "app.Person", "billingAddress",
                null);
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "people", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, billing,
                        Field.of("app.Person", "address", "address", "app.Address"),
                        Field.of("app.Person", "billingAddress", "billingAddress", "app.Address"),
                        Field.of("app.Address", "street", "street", "java.lang.String")),
                List.of(Edge.local(ingress.id(), ingress.id(), billing.id(), 1, List.of())), List.of(), List.of(),
                List.of());

        Map<String, String> requirements = Exposures.of(graph).stream()
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));

        assertThat(requirements).containsEntry("address.street", "none")
                .containsEntry("billingAddress.street", "ROLE_BILLING");
    }

    @Test
    void aDeclassifiedFieldKeepsItsOwnCheck() {
        // ProfileView.salaryBand is derived from Account.salary and declassified; its getter checks MANAGER.
        Ingress ingress = Ingress.of("GET", "/profiles/{id}", CodeRef.ofMethod("app.Controller", "profile()"))
                .withResponse(new Payload("app.ProfileView", false));
        AuthorizationLocation band = field("location:FIELD:band", "ROLE_MANAGER", "app.ProfileView", "salaryBand",
                null);
        AuthorizationLocation salary = field("location:FIELD:salary", "ROLE_PAYROLL", "app.Account", "salary", null);
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "people", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, band, salary,
                        Field.of("app.ProfileView", "salaryBand", "salaryBand", "java.lang.String").declassify(),
                        Field.of("app.Account", "salary", "salary", "java.math.BigDecimal")),
                List.of(Edge.local(ingress.id(), ingress.id(), salary.id(), 1, List.of()),
                        Edge.local(ingress.id(), salary.id(), band.id(), 2, List.of())),
                List.of(Flow.local(ingress.id(), Field.id("app.Account", "salary"),
                        Field.id("app.ProfileView", "salaryBand"), FieldSource.COMPUTED)), List.of(), List.of());

        Exposures.Exposure exposure = Exposures.of(graph).stream()
                .filter(candidate -> candidate.field().equals("salaryBand")).findFirst().orElseThrow();

        // The source's check no longer counts; the field's own still does.
        assertThat(exposure.requirement()).isEqualTo("ROLE_MANAGER");
        assertThat(exposure.sources()).containsExactly("people/field:app.ProfileView.salaryBand");
    }

    @Test
    void aFieldCheckOnThePathTwiceCountsOnce() {
        // The getter is called twice on the way to the response.
        Ingress ingress = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Controller", "account()"))
                .withResponse(new Payload("app.Account", false));
        AuthorizationLocation getter = field("location:FIELD:getter", "ROLE_GETTER", "app.Account", "ssn", null);
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, getter, Field.of("app.Account", "ssn", "ssn",
                        "java.lang.String")),
                List.of(Edge.local(ingress.id(), ingress.id(), getter.id(), 1, List.of()),
                        Edge.local(ingress.id(), ingress.id(), getter.id(), 2, List.of("app.Audit.log"))),
                List.of(), List.of(), List.of());

        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.field().equals("ssn")).singleElement()
                .satisfies(exposure -> assertThat(exposure.steps()).extracting(Exposures.Step::location)
                        .containsExactly("bank/location:FIELD:getter"));
    }

    @Test
    void theDiffsKeyUnnamesRouteVariablesButKeepsTheirPatterns() {
        assertThat(Exposures.Exposure.key("files", "GET /files/{id}", "name")).isEqualTo("files GET /files/{} name");
        assertThat(Exposures.Exposure.key("files", "GET /files/{name:.+}", "")).isEqualTo("files GET /files/{:.+}");
        assertThat(Exposures.Exposure.key("files", "GET /files/{id:[0-9]{3}}/x", ""))
                .isEqualTo("files GET /files/{:[0-9]{3}}/x");
        assertThat(Exposures.Exposure.key("files", "GET /files/{*path}", "")).isEqualTo("files GET /files/{*}");
        // A brace that doesn't close takes the rest of the route as the variable.
        assertThat(Exposures.Exposure.key("files", "GET /files/{id:[0-9]", "")).isEqualTo("files GET /files/{:[0-9]}");
    }

    /**
     * The guarded getter is reached on one branch only: on the other the value isn't the guarded one.
     */
    @Test
    void aFieldCheckOnSomeBranchesOnlyDoesntGuardItsField() {
        Ingress ingress = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Controller", "account()"))
                .withResponse(new Payload("app.Account", false));
        AuthorizationLocation getter = field("location:FIELD:getter", "ROLE_GETTER", "app.Account", "ssn", null);
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, getter,
                        Field.of("app.Account", "ssn", "ssn", "java.lang.String")),
                List.of(Edge.local(ingress.id(), ingress.id(), getter.id(), 1, List.of()).asConditional(true)),
                List.of(), List.of(), List.of());

        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.field().equals("ssn")).singleElement()
                .satisfies(exposure -> assertThat(exposure.steps()).isEmpty());
    }

    @Test
    void aValueThatGoesRoundIsFollowedOnce() {
        // The view is built from the account, and the account updated from the view.
        Ingress ingress = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Controller", "account()"))
                .withResponse(new Payload("app.View", false));
        AuthorizationLocation getter = field("location:FIELD:getter", "ROLE_GETTER", "app.Account", "ssn", null);
        String account = Field.id("app.Account", "ssn");
        String view = Field.id("app.View", "ssn");
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, getter,
                        Field.of("app.Account", "ssn", "ssn", "java.lang.String"),
                        Field.of("app.View", "ssn", "ssn", "java.lang.String")),
                List.of(Edge.local(ingress.id(), ingress.id(), getter.id(), 1, List.of())),
                List.of(Flow.local(ingress.id(), account, view, FieldSource.DIRECT),
                        Flow.local(ingress.id(), view, account, FieldSource.DIRECT)), List.of(), List.of());

        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.field().equals("ssn")).singleElement()
                .satisfies(exposure -> {
                    assertThat(exposure.requirement()).isEqualTo("ROLE_GETTER");
                    assertThat(exposure.lineage()).extracting(Flow::from).containsExactly("bank/" + account,
                            "bank/" + view);
                });
    }

    @Test
    void aValueAHandlerDerivesPassesOnlyTheChecksThatThrow() {
        // iban's getter masks for callers without TELLER; a second check throws without CUSTOMER.
        Ingress ingress = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Controller", "account()"))
                .withResponse(new Payload("app.Account", false));
        AuthorizationLocation masking = new AuthorizationLocation("location:FIELD:masking", "@PostAuthorize",
                AuthorizationLocation.Scope.FIELD, AuthorizationLocation.Phase.POST,
                Requirement.anyAuthority(List.of("ROLE_TELLER")), CodeRef.ofMethod("app.Account", "getIban()"),
                "iban", null, new AuthorizationLocation.Denial(AuthorizationLocation.Denial.Kind.HANDLER, "app.Mask"),
                true);
        AuthorizationLocation throwing = field("location:FIELD:throwing", "ROLE_CUSTOMER", "app.Account", "iban",
                null);
        String iban = Field.id("app.Account", "iban");
        String masked = Field.id("app.Account", "iban(denied)");
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, masking, throwing,
                        Field.of("app.Account", "iban", "iban", "java.lang.String"),
                        Field.of("app.Account", "iban(denied)", "iban(denied)", "java.lang.String")),
                List.of(Edge.local(ingress.id(), ingress.id(), masking.id(), 1, List.of()),
                        Edge.local(ingress.id(), masking.id(), throwing.id(), 2, List.of())),
                List.of(Flow.local(ingress.id(), iban, masked, FieldSource.MASKED)), List.of(), List.of());

        assertThat(Exposures.of(graph).stream().collect(Collectors.toMap(Exposures.Exposure::field,
                Exposures.Exposure::requirement)))
                .containsEntry("iban", "ROLE_TELLER and ROLE_CUSTOMER")
                .containsEntry("iban(denied)", "ROLE_CUSTOMER");
    }

    @Test
    void aDerivedValueIsInTheResponsesOfThePathsWhoseCheckHandsItOut() {
        Ingress proxied = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Controller", "account()"))
                .withResponse(new Payload("app.Account", false));
        Ingress raw = Ingress.of("GET", "/raw/{id}", CodeRef.ofMethod("app.Controller", "raw()"))
                .withResponse(new Payload("app.Account", false));
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(proxied, raw,
                        Field.of("app.Account", "iban", "iban", "java.lang.String"),
                        Field.of("app.Account", "iban(denied)", "iban(denied)", "java.lang.String")),
                List.of(), List.of(Flow.local(proxied.id(), Field.id("app.Account", "iban"),
                        Field.id("app.Account", "iban(denied)"), FieldSource.MASKED)), List.of(), List.of());

        assertThat(Exposures.of(graph)).filteredOn(exposure -> !exposure.field().isEmpty())
                .extracting(exposure -> exposure.endpoint() + " " + exposure.field())
                .containsExactlyInAnyOrder("GET /accounts/{id} iban", "GET /accounts/{id} iban(denied)",
                        "GET /raw/{id} iban");
    }

    private Map<String, String> requirements() {
        return Exposures.of(graph).stream()
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
    }

    private static ApplicationGraph graph() {
        Ingress ingress = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Controller", "account()"))
                .withResponse(new Payload("app.Account", false));
        List<AuthorizationLocation> checks = List.of(
                field("location:FIELD:getter", "ROLE_GETTER", "app.Account", "ssn", null),
                field("location:FIELD:resolver", "ROLE_RESOLVER", "app.Controller", "ssn", "app.Account"),
                field("location:FIELD:team", "ROLE_TEAMS", "app.Controller", "team", "app.Account"));
        List<Node> nodes = new ArrayList<>(List.of(ingress,
                Field.of("app.Account", "ssn", "ssn", "java.lang.String"),
                Field.of("app.Account", "team", "team", "app.Team"),
                Field.of("app.Team", "name", "name", "java.lang.String")));
        nodes.addAll(checks);
        List<Edge> edges = new ArrayList<>();
        String previous = ingress.id();
        for (AuthorizationLocation check : checks) {
            edges.add(Edge.local(ingress.id(), previous, check.id(), edges.size() + 1, List.of()));
            previous = check.id();
        }
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080, AuthoritySource.UNKNOWN,
                nodes, edges, List.of(), List.of(), List.of());
    }

    private static AuthorizationLocation field(String id, String role, String targetClass, String field,
            String owner) {
        return new AuthorizationLocation(id, "@PreAuthorize", AuthorizationLocation.Scope.FIELD,
                AuthorizationLocation.Phase.PRE, Requirement.anyAuthority(List.of(role)),
                CodeRef.ofMethod(targetClass, "m()"), field, null, AuthorizationLocation.Denial.THROW, true, owner);
    }
}
