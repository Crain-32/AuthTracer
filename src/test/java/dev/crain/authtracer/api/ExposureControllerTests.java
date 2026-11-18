package dev.crain.authtracer.api;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.TraceSource;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:authtracer-exposures-test;DB_CLOSE_DELAY=-1")
@AutoConfigureMockMvc
@DirtiesContext
class ExposureControllerTests {

    private static final String SSN = "field:back.Employee.ssn";

    @TestConfiguration
    static class NoTraces {

        @Bean
        @Primary
        TraceSource noTraces() {
            return ZipkinTraces.of(List.of());
        }
    }

    @Autowired
    MockMvc mvc;

    @Test
    void postedApplicationGraphTiesFieldChecksToTheirFields() throws Exception {
        mvc.perform(post("/api/exposures").contentType(MediaType.APPLICATION_JSON).content(GraphJson.write(back())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[0].field").value(""))
                .andExpect(jsonPath("$[0].requirement").value("authenticated"))
                .andExpect(jsonPath("$[0].adds").doesNotExist())
                .andExpect(jsonPath("$[1].field").value("ssn"))
                .andExpect(jsonPath("$[1].adds").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$[1].fieldId").value("back/field:back.EmployeeResponse.ssn"))
                .andExpect(jsonPath("$[1].requirement").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$[1].steps[1].scope").value("FIELD"))
                .andExpect(jsonPath("$[1].steps[1].guards").value("back/" + SSN))
                .andExpect(jsonPath("$[1].lineage[0].from").value("back/" + SSN))
                .andExpect(jsonPath("$[1].lineage[0].source").value("DIRECT"));
    }

    @Test
    void linkedSystemCarriesRequirementsAndLineageAcrossServices() throws Exception {
        mvc.perform(get("/api/system/exposures")).andExpect(status().isNotFound());
        publish(back());
        publish(front());
        mvc.perform(post("/api/system/link")).andExpect(status().isOk());

        mvc.perform(get("/api/system/exposures"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.service == 'front' && @.field == 'last4')].requirement")
                        .value("ROLE_ADMIN"))
                .andExpect(jsonPath("$[?(@.service == 'front' && @.field == 'last4')].sources[0]")
                        .value("back/" + SSN))
                .andExpect(jsonPath("$[?(@.service == 'front' && @.field == 'last4')].lineage[*].kind")
                        .value(contains("LOCAL", "NETWORK", "LOCAL")));
    }

    @Test
    void somethingElseThanAGraphIsABadRequest() throws Exception {
        mvc.perform(post("/api/exposures").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"base\":\"a\",\"head\":\"b\",\"changes\":[]}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/exposures").contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest());
        // A graph, but one its exposures can't be read from: a field id that isn't one.
        ApplicationGraph badField = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(new Field("app.Account.iban", "app.Account", "iban", "iban",
                        "java.lang.String", List.of(), false, null)), List.of(), List.of(), List.of(), List.of());
        mvc.perform(post("/api/exposures").contentType(MediaType.APPLICATION_JSON).content(GraphJson.write(badField)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void aPermittedRequestReadsAsPermitAll() throws Exception {
        Ingress ingress = Ingress.of("GET", "/health", CodeRef.ofMethod("back.Health", "get()"));
        AuthorizationLocation open = location("location:HTTP_REQUEST:back.Security:0:/health",
                AuthorizationLocation.Scope.HTTP_REQUEST, Requirement.permitAll(),
                CodeRef.ofMethod("back.Security", "chain()"), null);
        ApplicationGraph graph = graph("back", 9001, List.of(ingress, open),
                List.of(Edge.local(ingress.id(), ingress.id(), open.id(), 1, List.of())), List.of());

        mvc.perform(post("/api/exposures").contentType(MediaType.APPLICATION_JSON).content(GraphJson.write(graph)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].requirement").value("none"))
                .andExpect(jsonPath("$[0].steps[0].requirement").value("permitAll"))
                .andExpect(jsonPath("$[0].steps[0].scope").value("HTTP_REQUEST"));
    }

    @Test
    void aSystemGraphWhoseLinksAreNotBetweenServicesIsABadRequest() throws Exception {
        // A message sent to a topic, without the services the ids are of.
        SystemGraph unqualified = new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(back(), front()),
                List.of(new Edge("egress:front.Orders#send() KAFKA orders", "ingress:KAFKA orders",
                        Edge.Kind.NETWORK_INFERRED, null, 0, List.of(), true)), List.of(), List.of(), List.of(),
                List.of());

        mvc.perform(post("/api/exposures").contentType(MediaType.APPLICATION_JSON)
                        .content(GraphJson.write(unqualified)))
                .andExpect(status().isBadRequest())
                .andExpect(status().reason(startsWith("A link joins qualified ids")));
    }

    private void publish(ApplicationGraph graph) throws Exception {
        mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON).content(GraphJson.write(graph)))
                .andExpect(status().isCreated());
    }

    /**
     * {@code GET /employees/{id}}: authenticated, and the ssn field only for admins.
     */
    private static ApplicationGraph back() {
        Ingress ingress = Ingress.of("GET", "/employees/{id}", CodeRef.ofMethod("back.Controller", "get(long)"))
                .withResponse(new Payload("back.EmployeeResponse", false));
        AuthorizationLocation request = location("location:HTTP_REQUEST:any", AuthorizationLocation.Scope.HTTP_REQUEST,
                Requirement.authenticated(), CodeRef.ofMethod("back.Security", "chain()"), null);
        AuthorizationLocation ssnCheck = location("location:FIELD:back.Employee#getSsn()",
                AuthorizationLocation.Scope.FIELD, Requirement.anyAuthority(List.of("ROLE_ADMIN")),
                CodeRef.ofMethod("back.Employee", "getSsn()"), "ssn");
        List<Node> nodes = List.of(ingress, request, ssnCheck, Field.of("back.Employee", "ssn", "ssn", "java.lang.String"),
                Field.of("back.EmployeeResponse", "ssn", "ssn", "java.lang.String"));
        List<Edge> edges = List.of(Edge.local(ingress.id(), ingress.id(), request.id(), 1, List.of()),
                Edge.local(ingress.id(), request.id(), ssnCheck.id(), 2, List.of()));
        List<Flow> flows = List.of(Flow.local(ingress.id(), SSN, "field:back.EmployeeResponse.ssn",
                FieldSource.DIRECT));
        return graph("back", 9001, nodes, edges, flows);
    }

    /**
     * {@code GET /profiles/{id}} calls the back service and returns the last four digits of the ssn.
     */
    private static ApplicationGraph front() {
        Ingress ingress = Ingress.of("GET", "/profiles/{id}", CodeRef.ofMethod("front.Controller", "get(long)"))
                .withResponse(new Payload("front.Profile", false));
        Egress call = Egress.of("RestClient", "GET", "/employees/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Client", "get(long)"), new Payload("front.EmployeeDto", false));
        List<Node> nodes = List.of(ingress, call, Field.of("front.EmployeeDto", "ssn", "ssn", "java.lang.String"),
                Field.of("front.Profile", "last4", "last4", "java.lang.String"));
        List<Edge> edges = List.of(Edge.local(ingress.id(), ingress.id(), call.id(), 1, List.of()));
        List<Flow> flows = List.of(Flow.local(ingress.id(), "field:front.EmployeeDto.ssn", "field:front.Profile.last4",
                FieldSource.COMPUTED));
        return graph("front", 9000, nodes, edges, flows);
    }

    private static AuthorizationLocation location(String id, AuthorizationLocation.Scope scope,
            Requirement requirement, CodeRef target, String field) {
        return new AuthorizationLocation(id, "@PreAuthorize", scope, AuthorizationLocation.Phase.PRE, requirement,
                target, field, null, AuthorizationLocation.Denial.THROW, scope != AuthorizationLocation.Scope.HTTP_REQUEST);
    }

    private static ApplicationGraph graph(String service, int port, List<Node> nodes, List<Edge> edges,
            List<Flow> flows) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "r1", port, AuthoritySource.UNKNOWN,
                nodes, edges, flows, List.of(), List.of());
    }
}
