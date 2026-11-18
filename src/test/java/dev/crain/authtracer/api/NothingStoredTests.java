package dev.crain.authtracer.api;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import dev.crain.authtracer.link.TraceSource;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

/**
 * What the API answers before any graph is published: nothing to list, fetch or link.
 */
@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:authtracer-nothing-stored-test;DB_CLOSE_DELAY=-1")
@AutoConfigureMockMvc
@DirtiesContext
class NothingStoredTests {

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
    void thereIsNothingToListFetchOrLink() throws Exception {
        mvc.perform(get("/api/graphs")).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
        mvc.perform(get("/api/graphs/items").param("revision", "r1")).andExpect(status().isNotFound());
        mvc.perform(get("/api/system")).andExpect(status().isNotFound());
        mvc.perform(post("/api/system/link")).andExpect(status().isUnprocessableContent());
        mvc.perform(get("/api/system")).andExpect(status().isNotFound());
    }
}
