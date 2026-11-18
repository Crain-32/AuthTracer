package dev.crain.authtracer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.regex.Pattern;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.link.TraceSource;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:authtracer-test;DB_CLOSE_DELAY=-1")
@AutoConfigureMockMvc
@DirtiesContext
class AuthTracerApplicationTests {

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

    @Value("${server.address}")
    String address;

    @Test
    void theApiAnswersThisMachineOnlyByDefault() {
        // It has no authentication of its own.
        assertThat(address).isEqualTo("127.0.0.1");
    }

    @Test
    void publishListFetchAndLink() throws Exception {
        Egress call = Egress.of("RestClient", "GET", "/items/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Client", "get(long)"), null);
        Ingress items = Ingress.of("GET", "/items/{id}", CodeRef.ofMethod("back.Items", "get(long)"));
        publish(graph("front", 9000, call));
        publish(graph("back", 9001, items));

        mvc.perform(get("/api/graphs")).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(2)));
        mvc.perform(get("/api/graphs/back")).andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes[0].route").value("/items/{id}"));
        mvc.perform(get("/api/graphs/nope")).andExpect(status().isNotFound());

        mvc.perform(post("/api/system/link")).andExpect(status().isOk())
                .andExpect(jsonPath("$.links", hasSize(1)))
                .andExpect(jsonPath("$.links[0].kind").value("NETWORK_INFERRED"));
        mvc.perform(get("/api/system")).andExpect(status().isOk()).andExpect(jsonPath("$.services", hasSize(2)));
    }

    /**
     * The UI is built by Vite (frontend/) into the static resources: the page, and everything it loads, is served.
     */
    @Test
    void servesTheUi() throws Exception {
        mvc.perform(get("/")).andExpect(status().isOk()).andExpect(forwardedUrl("index.html"));
        String page = mvc.perform(get("/index.html")).andExpect(status().isOk())
                .andExpect(content().string(containsString("<div id=\"root\">")))
                .andReturn().getResponse().getContentAsString();
        List<String> loads = Pattern.compile("(?:src|href)=\"(/[^\"]+)\"").matcher(page).results()
                .map(match -> match.group(1)).toList();
        assertThat(loads).anyMatch(path -> path.endsWith(".js")).anyMatch(path -> path.endsWith(".css"));
        for (String path : loads) {
            mvc.perform(get(path)).andExpect(status().isOk());
        }
    }

    private void publish(ApplicationGraph graph) throws Exception {
        mvc.perform(post("/api/graphs").contentType(MediaType.APPLICATION_JSON).content(GraphJson.write(graph)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.service").value(graph.service()));
    }

    private static ApplicationGraph graph(String service, int port, dev.crain.authtracer.graph.Node node) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "r1", port, AuthoritySource.UNKNOWN,
                List.of(node), List.of(), List.of(), List.of(), List.of());
    }
}
