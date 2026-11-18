package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Spring Framework 7.0.9 RequestMappingInfo#combine: a class's @RequestMapping methods and params join each handler's.
 */
class ClassMappingsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("classmappings");

    @Test
    void aClassesMethodsJoinItsHandlers() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:POST /accounts/close", "ingress:GET /accounts/summary",
                        "ingress:POST /accounts/summary")
                .doesNotContain("ingress:* /accounts/close");
        assertThat(rule(graph, "POST /accounts/summary").requirement().authorities()).containsExactly("ROLE_TELLER");
    }

    @Test
    void aClassesParamsJoinItsHandlers() {
        assertThat(graph.node("ingress:GET /v2/items?page&tenant")).isPresent();
    }

    @Test
    void consumesAndProducesAreTheHandlersWhereItHasThem() {
        RequestMappings.MappingInfo type = new RequestMappings.MappingInfo(List.of("/a"), List.of("*"), "",
                List.of("header:X-Api=2", "consumes:application/json", "produces:text/plain"));
        RequestMappings.MappingInfo method = new RequestMappings.MappingInfo(List.of("/b"), List.of("GET"), "q",
                List.of("produces:application/json"));
        RequestMappings.MappingInfo combined = RequestMappings.combine(type, method);
        assertThat(combined.methods()).containsExactly("GET");
        assertThat(combined.params()).isEqualTo("q");
        assertThat(combined.conditions()).containsExactly("header:X-Api=2", "consumes:application/json",
                "produces:application/json");
    }
}
