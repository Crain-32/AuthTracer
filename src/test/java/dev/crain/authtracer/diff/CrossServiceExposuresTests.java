package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;

/**
 * Fields that come from another service: what the called endpoint asks counts for them, nested ones included.
 */
class CrossServiceExposuresTests {

    private static final Ingress PROFILE = Ingress.of("GET", "/profiles/{id}", CodeRef.ofMethod("a.Profiles",
            "get(long)")).withResponse(new Payload("a.EmployeeDto", false));
    private static final Ingress EMPLOYEE = Ingress.of("GET", "/employees/{id}", CodeRef.ofMethod("b.Employees",
            "get(long)")).withResponse(new Payload("b.Employee", false));

    @Test
    void aFieldNestedInTheRemoteResponseCarriesTheCalleesChecksAndLabels() {
        // B's address check guards the street under it; B labels the street PII, under an admin-only Org policy.
        ApplicationGraph b = service("employee-service", 9001, List.of(EMPLOYEE,
                location("location:METHOD:b.Employees#get", AuthorizationLocation.Scope.METHOD, "ROLE_HR", null,
                        "b.Employees"),
                location("location:FIELD:b.Employee#getAddress()", AuthorizationLocation.Scope.FIELD, "ROLE_ADDRESS",
                        "address", "b.Employee"),
                Field.of("b.Employee", "address", "address", "b.Address"),
                Field.of("b.Address", "street", "street", "java.lang.String").withLabels(List.of("PII"))),
                EMPLOYEE.id(), List.of("location:METHOD:b.Employees#get", "location:FIELD:b.Employee#getAddress()"),
                List.of(new ProvidedFact(ProvidedFact.Kind.POLICY, "PII", List.of("PII"), "hasRole('ADMIN')", null,
                        ProvidedFact.Origin.ORG)));
        SystemGraph system = relay(b, List.of());

        Map<String, Exposure> profile = Exposures.of(system).stream()
                .filter(exposure -> exposure.service().equals("profile-service"))
                .collect(Collectors.toMap(Exposure::field, exposure -> exposure));

        assertThat(profile.get("address").requirement()).isEqualTo("ROLE_HR and ROLE_ADDRESS");
        Exposure street = profile.get("address.street");
        assertThat(street.requirement()).isEqualTo("ROLE_HR and ROLE_ADDRESS");
        assertThat(street.labels()).containsExactly("PII");
        assertThat(street.sources()).containsExactly("employee-service/field:b.Address.street");
        assertThat(street.violations()).extracting(Policies.Violation::label).containsExactly("PII");
    }

    @Test
    void aCallThatMayReachSeveralServicesNeedsWhatTheWeakestAsks() {
        // No base URL to tell B from C: the call links to both, and the name comes from one of them.
        ApplicationGraph b = endpoint("employee-service", 9001, "ROLE_B");
        ApplicationGraph c = endpoint("identity-service", 9002, "ROLE_C");

        Exposure name = name(relay(b, List.of(c), null));

        assertThat(name.requirement()).isEqualTo("any of [ROLE_B, ROLE_C]");
        assertThat(name.sources()).containsExactlyInAnyOrder("employee-service/field:b.Employee.name",
                "identity-service/field:b.Employee.name");

        // C drops its check: the name can now be had for less.
        DiffReport report = GraphDiff.compare(relay(b, List.of(c), null),
                relay(b, List.of(endpoint("identity-service", 9002, null)), null));
        assertThat(report.changes()).anySatisfy(change -> {
            assertThat(change.kind()).isEqualTo(DiffReport.Kind.WEAKENED);
            assertThat(change.service()).isEqualTo("profile-service");
            assertThat(change.field()).isEqualTo("name");
        });
    }

    @Test
    void aCallWhoseAnswerIsNotReadCarriesNoField() {
        // A also posts an audit record on the way, and doesn't read the answer.
        Egress audit = Egress.of("RestClient", "POST", "/audit", "http://localhost:9003", null,
                CodeRef.ofMethod("a.Audit", "record()"), null).withCredentials(Credentials.RELAY, "test");
        Ingress record = Ingress.of("POST", "/audit", CodeRef.ofMethod("d.Audit", "record()"));
        ApplicationGraph d = service("payroll-service", 9003, List.of(record), record.id(), List.of(), List.of());

        Exposure name = name(relay(endpoint("employee-service", 9001, "ROLE_B"), List.of(d), "http://localhost:9001",
                List.of(audit)));

        assertThat(name.requirement()).isEqualTo("ROLE_B");
        assertThat(name.sources()).containsExactly("employee-service/field:b.Employee.name");
    }

    @Test
    void aFieldFromAnEndpointThatReturnsWhatIsNotKnownIsTheCallersOwn() {
        Ingress unknown = Ingress.of("GET", "/employees/{id}", CodeRef.ofMethod("b.Employees", "get(long)"));
        ApplicationGraph b = service("employee-service", 9001, List.of(unknown, location("location:METHOD:b.Employees#get",
                AuthorizationLocation.Scope.METHOD, "ROLE_B", null, "b.Employees")), unknown.id(),
                List.of("location:METHOD:b.Employees#get"), List.of());

        Exposure name = name(relay(b, List.of()));

        assertThat(name.requirement()).isEqualTo("authenticated");
        assertThat(name.sources()).containsExactly("profile-service/field:a.EmployeeDto.name");
    }

    @Test
    void checksPastACallWithTheServicesOwnCredentialsDoNotCountForTheCaller() {
        // A calls B as itself; B relays that token to C, so C checks A, not A's caller, and neither B's nor C's
        // check keeps A's caller from C's name.
        Egress toC = Egress.of("RestClient", "GET", "/people/{id}", "http://localhost:9002", null,
                CodeRef.ofMethod("b.PersonClient", "get(long)"), new Payload("b.Employee", false))
                .withCredentials(Credentials.RELAY, "test");
        ApplicationGraph b = service("employee-service", 9001, List.of(EMPLOYEE, toC, location("location:METHOD:b.Employees#get",
                AuthorizationLocation.Scope.METHOD, "ROLE_B", null, "b.Employees"),
                Field.of("b.Employee", "name", "name", "java.lang.String")), EMPLOYEE.id(),
                List.of("location:METHOD:b.Employees#get", toC.id()), List.of());
        Ingress person = Ingress.of("GET", "/people/{id}", CodeRef.ofMethod("c.People", "get(long)"))
                .withResponse(new Payload("c.Person", false));
        ApplicationGraph c = service("identity-service", 9002, List.of(person, location("location:METHOD:c.People#get",
                AuthorizationLocation.Scope.METHOD, "ROLE_C", null, "c.People"),
                Field.of("c.Person", "name", "name", "java.lang.String")), person.id(),
                List.of("location:METHOD:c.People#get"), List.of());
        Egress asItself = Egress.of("RestClient", "GET", "/employees/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("a.EmployeeClient", "get(long)"), new Payload("a.EmployeeDto", false))
                .withCredentials(Credentials.OAUTH2_CLIENT, "test");
        ApplicationGraph a = service("profile-service", 9000, List.of(PROFILE, asItself,
                Field.of("a.EmployeeDto", "name", "name", "java.lang.String")), PROFILE.id(),
                List.of(asItself.id()), List.of());

        Exposure name = name(new Linker().link(List.of(a, b, c), ZipkinTraces.of(List.of())));

        assertThat(name.sources()).containsExactly("identity-service/field:c.Person.name");
        assertThat(name.requirement()).isEqualTo("none");
    }

    @Test
    void aRemoteResponseThatHoldsItsOwnTypeIsReadOnce() {
        // An employee's manager is an employee too.
        ApplicationGraph b = service("employee-service", 9001, List.of(EMPLOYEE, location("location:METHOD:b.Employees#get",
                AuthorizationLocation.Scope.METHOD, "ROLE_B", null, "b.Employees"),
                Field.of("b.Employee", "name", "name", "java.lang.String"),
                Field.of("b.Employee", "manager", "manager", "b.Employee")), EMPLOYEE.id(),
                List.of("location:METHOD:b.Employees#get"), List.of());

        Exposure name = assertTimeoutPreemptively(Duration.ofSeconds(10), () -> name(relay(b, List.of())));

        assertThat(name.requirement()).isEqualTo("ROLE_B");
        assertThat(name.sources()).containsExactly("employee-service/field:b.Employee.name");
    }

    @Test
    void aFieldReceivedFromOneCallIsNotTheOtherCallsToo() {
        // A reads an employee from two of B's endpoints, each behind a check of its own, on two of its own.
        Ingress search = Ingress.of("GET", "/search", CodeRef.ofMethod("a.Search", "find()"))
                .withResponse(new Payload("a.EmployeeDto", false));
        Egress get = Egress.of("RestClient", "GET", "/employees/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("a.EmployeeClient", "get(long)"), new Payload("a.EmployeeDto", false))
                .withCredentials(Credentials.RELAY, "test");
        Egress find = Egress.of("RestClient", "GET", "/employees/search", "http://localhost:9001", null,
                CodeRef.ofMethod("a.EmployeeClient", "find()"), new Payload("a.EmployeeDto", false))
                .withCredentials(Credentials.RELAY, "test");
        ApplicationGraph a = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "profile-service", "test", 9000,
                AuthoritySource.UNKNOWN, new ArrayList<>(List.of(PROFILE, search, get, find,
                        Field.of("a.EmployeeDto", "name", "name", "java.lang.String"))),
                List.of(Edge.local(PROFILE.id(), PROFILE.id(), get.id(), 1, List.of()),
                        Edge.local(search.id(), search.id(), find.id(), 1, List.of())), List.of(), List.of(),
                List.of());
        Ingress searchEmployees = Ingress.of("GET", "/employees/search", CodeRef.ofMethod("b.Employees", "find()"))
                .withResponse(new Payload("b.Employee", false));
        AuthorizationLocation getCheck = location("location:METHOD:b.Employees#get",
                AuthorizationLocation.Scope.METHOD, "ROLE_B", null, "b.Employees");
        AuthorizationLocation findCheck = location("location:METHOD:b.Employees#find",
                AuthorizationLocation.Scope.METHOD, "ROLE_SEARCH", null, "b.Employees");
        ApplicationGraph b = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "employee-service", "test", 9001,
                AuthoritySource.UNKNOWN, new ArrayList<>(List.of(EMPLOYEE, searchEmployees, getCheck, findCheck,
                        Field.of("b.Employee", "name", "name", "java.lang.String"))),
                List.of(Edge.local(EMPLOYEE.id(), EMPLOYEE.id(), getCheck.id(), 1, List.of()),
                        Edge.local(searchEmployees.id(), searchEmployees.id(), findCheck.id(), 1, List.of())),
                List.of(), List.of(), List.of());
        SystemGraph system = new Linker().link(List.of(a, b), ZipkinTraces.of(List.of()));

        Map<String, Exposure> names = Exposures.of(system).stream()
                .filter(exposure -> exposure.service().equals("profile-service") && exposure.field().equals("name"))
                .collect(Collectors.toMap(Exposure::endpoint, exposure -> exposure));

        // The same field of B's comes over both calls: each endpoint's lineage has its own.
        Exposure profile = names.get(PROFILE.endpoint());
        assertThat(profile.requirement()).isEqualTo("ROLE_B");
        assertThat(profile.lineage()).filteredOn(flow -> flow.kind() == Flow.Kind.NETWORK).extracting(Flow::path)
                .containsExactly("profile-service/" + get.id());
        Exposure found = names.get(search.endpoint());
        assertThat(found.requirement()).isEqualTo("ROLE_SEARCH");
        assertThat(found.lineage()).filteredOn(flow -> flow.kind() == Flow.Kind.NETWORK).extracting(Flow::path)
                .containsExactly("profile-service/" + find.id());
    }

    @Test
    void whatAListenerKeepsOfWhatItsCallReturnedComesFromTheCallee() {
        Exposure name = Exposures.of(new Linker().link(List.of(ledger(null), endpoint("employee-service", 9001,
                "ROLE_B")), ZipkinTraces.of(List.of()))).stream()
                .filter(exposure -> exposure.field().equals("employeeName")).findFirst().orElseThrow();

        assertThat(name.sources()).containsExactly("employee-service/field:b.Employee.name");
        assertThat(name.lineage()).extracting(Flow::kind).containsExactly(Flow.Kind.LOCAL, Flow.Kind.NETWORK);
        // No caller asked for the call: B's check is on A's own token, not on whoever reads the ledger.
        assertThat(name.requirement()).doesNotContain("ROLE_B");
    }

    @Test
    void aDiagonalEscalationsExampleIsARouteOfTheChangedServiceWhenItHasOne() {
        // B's name is read behind ROLE_B in B, and behind ROLE_A in A's ledger: neither asks less than the other.
        Ingress export = Ingress.of("GET", "/export/{id}", CodeRef.ofMethod("b.Export", "get(long)"))
                .withResponse(new Payload("b.Employee", false));
        ApplicationGraph base = endpoint("employee-service", 9001, "ROLE_B");
        List<Node> nodes = new ArrayList<>(base.nodes());
        nodes.add(export);
        ApplicationGraph head = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, base.service(), "head",
                base.port(), base.authoritySource(), nodes, base.edges(), List.of(), List.of(), List.of());

        DiffReport report = GraphDiff.compare(new Linker().link(List.of(ledger("ROLE_A"), base),
                ZipkinTraces.of(List.of())), new Linker().link(List.of(ledger("ROLE_A"), head),
                ZipkinTraces.of(List.of())));

        // B's own read, not A's ledger, though A's comes first by name: what B's author knows.
        assertThat(report.changes()).filteredOn(change -> change.kind() == DiffReport.Kind.DIAGONAL_ESCALATION)
                .singleElement().satisfies(change -> {
                    assertThat(change.endpoint()).isEqualTo("GET /export/{id}");
                    assertThat(change.before()).isEqualTo("ROLE_B");
                    assertThat(change.message()).endsWith("(e.g. GET /employees/{id} name)");
                });
    }

    /**
     * A's listener fetches an employee from B with A's own token and keeps the name; A's {@code GET /changes} serves
     * what it kept, behind a role check if one is given.
     */
    private static ApplicationGraph ledger(String role) {
        Ingress listener = Ingress.of("KAFKA", "salary.changed", CodeRef.ofMethod("a.Changes", "changed(a.Changed)"))
                .withRequest(new Payload("a.Changed", false));
        Ingress changes = Ingress.of("GET", "/changes", CodeRef.ofMethod("a.Ledger", "changes()"))
                .withResponse(new Payload("a.Change", true));
        Egress asItself = Egress.of("RestClient", "GET", "/employees/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("a.EmployeeClient", "get(long)"), new Payload("a.EmployeeDto", false))
                .withCredentials(Credentials.OAUTH2_CLIENT, "test");
        List<Node> nodes = new ArrayList<>(List.of(listener, changes, asItself,
                Field.of("a.Changed", "employeeId", "employeeId", "long"),
                Field.of("a.EmployeeDto", "name", "name", "java.lang.String"),
                Field.of("a.Change", "employeeName", "employeeName", "java.lang.String")));
        List<Edge> edges = new ArrayList<>(List.of(Edge.local(listener.id(), listener.id(), asItself.id(), 1,
                List.of())));
        if (role != null) {
            AuthorizationLocation check = location("location:METHOD:a.Ledger#changes",
                    AuthorizationLocation.Scope.METHOD, role, null, "a.Ledger");
            nodes.add(check);
            edges.add(Edge.local(changes.id(), changes.id(), check.id(), 1, List.of()));
        }
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "profile-service", "test", 9000,
                AuthoritySource.UNKNOWN, nodes, edges, List.of(Flow.local(listener.id(), "field:a.EmployeeDto.name",
                        "field:a.Change.employeeName", FieldSource.DIRECT)), List.of(), List.of());
    }

    private static Exposure name(SystemGraph system) {
        return Exposures.of(system).stream()
                .filter(exposure -> exposure.service().equals("profile-service") && exposure.field().equals("name"))
                .findFirst().orElseThrow();
    }

    /**
     * B's (or C's) {@code GET /employees/{id}}, returning a name, behind a role check if one is given.
     */
    private static ApplicationGraph endpoint(String name, int port, String role) {
        List<Node> nodes = new ArrayList<>(List.of(EMPLOYEE, Field.of("b.Employee", "name", "name",
                "java.lang.String")));
        List<String> path = new ArrayList<>();
        if (role != null) {
            nodes.add(location("location:METHOD:b.Employees#get", AuthorizationLocation.Scope.METHOD, role, null,
                    "b.Employees"));
            path.add("location:METHOD:b.Employees#get");
        }
        return service(name, port, nodes, EMPLOYEE.id(), path, List.of());
    }

    private static SystemGraph relay(ApplicationGraph callee, List<ApplicationGraph> others) {
        return relay(callee, others, "http://localhost:9001");
    }

    /**
     * A's {@code GET /profiles/{id}} returns what its call to {@code GET /employees/{id}} returned, relaying the
     * caller's token.
     */
    private static SystemGraph relay(ApplicationGraph callee, List<ApplicationGraph> others, String baseUrl) {
        return relay(callee, others, baseUrl, List.of());
    }

    /**
     * @param calls other calls A makes first
     */
    private static SystemGraph relay(ApplicationGraph callee, List<ApplicationGraph> others, String baseUrl,
            List<Egress> calls) {
        Egress call = Egress.of("RestClient", "GET", "/employees/{id}", baseUrl, null,
                CodeRef.ofMethod("a.EmployeeClient", "get(long)"), new Payload("a.EmployeeDto", false))
                .withCredentials(Credentials.RELAY, "test");
        List<Node> nodes = new ArrayList<>(List.of(PROFILE, call,
                location("location:HTTP_REQUEST:a.Config:0:anyRequest", AuthorizationLocation.Scope.HTTP_REQUEST,
                        null, null, "a.Config"),
                Field.of("a.EmployeeDto", "name", "name", "java.lang.String"),
                Field.of("a.EmployeeDto", "address", "address", "a.AddressDto"),
                Field.of("a.AddressDto", "street", "street", "java.lang.String")));
        nodes.addAll(calls);
        List<String> path = new ArrayList<>(List.of("location:HTTP_REQUEST:a.Config:0:anyRequest"));
        calls.forEach(other -> path.add(other.id()));
        path.add(call.id());
        ApplicationGraph a = service("profile-service", 9000, nodes, PROFILE.id(), path, List.of());
        List<ApplicationGraph> services = new ArrayList<>(List.of(a, callee));
        services.addAll(others);
        return new Linker().link(services, ZipkinTraces.of(List.of()));
    }

    /**
     * @param path the nodes on the Ingress's path, in order
     */
    private static ApplicationGraph service(String name, int port, List<Node> nodes, String ingress,
            List<String> path, List<ProvidedFact> provided) {
        List<Edge> edges = new ArrayList<>();
        String previous = ingress;
        for (String id : path) {
            edges.add(Edge.local(ingress, previous, id, edges.size() + 1, List.of()));
            previous = id;
        }
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, name, "test", port, AuthoritySource.UNKNOWN,
                new ArrayList<>(nodes), edges, List.of(), provided, List.of());
    }

    /**
     * @param role the role the check asks for, {@code null} for {@code authenticated}
     */
    private static AuthorizationLocation location(String id, AuthorizationLocation.Scope scope, String role,
            String field, String className) {
        return new AuthorizationLocation(id, "@PreAuthorize", scope, AuthorizationLocation.Phase.PRE,
                role == null ? Requirement.authenticated() : Requirement.anyAuthority(List.of(role)),
                CodeRef.ofMethod(className, "m()"), field, null, AuthorizationLocation.Denial.THROW, true);
    }
}
