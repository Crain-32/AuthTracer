package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class UrisFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("uris");

    @Test
    void restTemplateUriArguments() {
        Egress entry = egress("RestTemplate", "/entries/latest");
        assertThat(entry.httpMethod()).isEqualTo("GET");
        assertThat(entry.baseUrl()).isEqualTo("http://ledger:7070");
        Egress remove = egress("RestTemplate", "/entries/{id}");
        assertThat(remove.httpMethod()).isEqualTo("DELETE");
        assertThat(remove.baseUrlExpression()).isEqualTo("${ledger.base-url}");
    }

    @Test
    void uriBuilderLambdasAndDefaultUriBuilderFactory() {
        Egress account = egress("RestClient", "/accounts/{id}");
        assertThat(account.httpMethod()).isEqualTo("GET");
        assertThat(account.baseUrl()).isEqualTo("http://accounts:6060");
    }

    @Test
    void fluentUriArguments() {
        assertThat(egress("WebClient", "/events").baseUrl()).isEqualTo("http://audit:4040");
    }

    @Test
    void handWiredHttpInterfaces() {
        assertThat(egress("HTTP interface", "/tickets/{id}").baseUrl()).isEqualTo("http://tickets:5050");
    }

    private Egress egress(String client, String uriTemplate) {
        List<Egress> found = graph.nodes(Egress.class).stream()
                .filter(egress -> egress.client().equals(client) && egress.uriTemplate().equals(uriTemplate)).toList();
        assertThat(found).as(client + " " + uriTemplate + " in " + graph.nodes(Egress.class)).hasSize(1);
        return found.getFirst();
    }
}
