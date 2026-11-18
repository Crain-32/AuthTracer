package dev.crain.authtracer.api;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.link.TraceSource;
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

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:authtracer-graphs-test;DB_CLOSE_DELAY=-1")
@AutoConfigureMockMvc
@DirtiesContext
class GraphControllerTests {

    @TestConfiguration
    static class UnreachableTraceStore {

        @Bean
        @Primary
        TraceSource unreachable() {
            return services -> {
                throw new UncheckedIOException("Can't reach Zipkin at http://localhost:9411",
                        new ConnectException("Connection refused"));
            };
        }
    }

    @Autowired
    MockMvc mvc;

    @Test
    void aGraphWhoseServiceIsNotANameIsABadRequest() throws Exception {
        Ingress ingress = Ingress.of("GET", "/items", CodeRef.ofMethod("app.Items", "list()"));
        for (String service : new String[] { null, " ", "a/b", "x".repeat(256) }) {
            mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON)
                    .content(GraphJson.write(graph(service, 9000, ingress)))).andExpect(status().isBadRequest());
        }
        mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON)
                .content(GraphJson.write(graph("x".repeat(255), 9000, ingress)))).andExpect(status().isCreated());
    }

    @Test
    void aGraphLinkingCouldNotReadIsABadRequestAndIsNotStored() throws Exception {
        Ingress ingress = Ingress.of("GET", "/items", CodeRef.ofMethod("app.Items", "list()"));
        List<ApplicationGraph> malformed = List.of(
                graph("no-route", 9000, new Ingress("ingress:GET ?", "GET", null, CodeRef.ofMethod("app.Items",
                        "list()"), null)),
                graph("bad-field", 9000, new Field("app.Account.iban", "app.Account", "iban", "iban",
                        "java.lang.String", List.of(), false, null)),
                facts("bad-pattern", ingress, new ProvidedFact(ProvidedFact.Kind.ENDPOINT_POLICY,
                        "GET /admin/**/users", List.of(), "hasRole('ADMIN')", null, ProvidedFact.Origin.LOCAL)),
                facts("no-requirement", ingress, new ProvidedFact(ProvidedFact.Kind.POLICY, "PII", List.of("PII"),
                        null, null, ProvidedFact.Origin.ORG)));
        for (ApplicationGraph graph : malformed) {
            mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON).content(GraphJson.write(graph)))
                    .andExpect(status().isBadRequest());
        }

        mvc.perform(get("/api/graphs/no-route")).andExpect(status().isNotFound());
        // What is stored still links.
        mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON)
                .content(GraphJson.write(graph("items", 9000, ingress)))).andExpect(status().isCreated());
        mvc.perform(post("/api/system/link")).andExpect(status().isOk());
    }

    @Test
    void aGraphIsFetchedAtARevisionOrItsLatest() throws Exception {
        Ingress ingress = Ingress.of("GET", "/items", CodeRef.ofMethod("app.Items", "list()"));
        for (String revision : List.of("r1", "r2")) {
            ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "revisions", revision,
                    9000, AuthoritySource.UNKNOWN, List.of(ingress), List.of(), List.of(), List.of(), List.of());
            mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON).content(GraphJson.write(graph)))
                    .andExpect(status().isCreated());
        }

        mvc.perform(get("/api/graphs/revisions").param("revision", "r1")).andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value("r1"));
        mvc.perform(get("/api/graphs/revisions")).andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value("r2"));
        mvc.perform(get("/api/graphs/revisions").param("revision", "r9")).andExpect(status().isNotFound());
    }

    @Test
    void aGraphWithProvidedFactsItsFilesAllowIsStoredWithThem() throws Exception {
        Ingress ingress = Ingress.of("GET", "/items", CodeRef.ofMethod("app.Items", "list()"));
        ProvidedFact sensitive = new ProvidedFact(ProvidedFact.Kind.SENSITIVE, "field:app.Item.name", List.of("PII"),
                null, null, ProvidedFact.Origin.ORG);

        mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON)
                .content(GraphJson.write(facts("facts", ingress, sensitive)))).andExpect(status().isCreated());
        mvc.perform(get("/api/graphs/facts")).andExpect(status().isOk())
                .andExpect(jsonPath("$.provided[0].subject").value("field:app.Item.name"));
    }

    @Test
    void anUnreachableTraceStoreLinksStatically() throws Exception {
        Egress call = Egress.of("RestClient", "GET", "/orders/{id}", "http://localhost:9101", null,
                CodeRef.ofMethod("front.Client", "get(long)"), null);
        Ingress orders = Ingress.of("GET", "/orders/{id}", CodeRef.ofMethod("back.Orders", "get(long)"));
        mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON)
                .content(GraphJson.write(graph("orders-front", 9100, call)))).andExpect(status().isCreated());
        mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON)
                .content(GraphJson.write(graph("orders-back", 9101, orders)))).andExpect(status().isCreated());

        mvc.perform(post("/api/system/link")).andExpect(status().isOk())
                .andExpect(jsonPath("$.links[?(@.from == 'orders-front/" + call.id() + "')]", hasSize(1)))
                .andExpect(jsonPath("$.observations", hasSize(0)));
    }

    private static ApplicationGraph facts(String service, Node node, ProvidedFact fact) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "r1", 9000, AuthoritySource.UNKNOWN,
                List.of(node), List.of(), List.of(), List.of(fact), List.of());
    }

    private static ApplicationGraph graph(String service, int port, Node node) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "r1", port, AuthoritySource.UNKNOWN,
                List.of(node), List.of(), List.of(), List.of(), List.of());
    }
}
