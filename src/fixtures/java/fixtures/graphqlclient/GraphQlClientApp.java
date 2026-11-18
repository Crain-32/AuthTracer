package fixtures.graphqlclient;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.graphql.client.HttpGraphQlClient;
import org.springframework.graphql.client.HttpSyncGraphQlClient;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Calls the graphql fixture's operations through Spring for GraphQL's clients.
 */
@Configuration
@EnableWebSecurity
class GraphQlClientApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /**
     * Relays the caller's token: the graphql service's checks count for this service's callers.
     */
    @Bean
    HttpGraphQlClient graphQlClient(WebClient.Builder builder) {
        return HttpGraphQlClient.builder(builder.filter(new ServletBearerExchangeFilterFunction()).build())
                .url("http://localhost:8095/api/graphql").build();
    }
}

record PersonView(String name, BigDecimal salary) {
}

@RestController
class PeopleController {

    private final HttpSyncGraphQlClient graphQl;

    PeopleController(RestClient.Builder builder) {
        this.graphQl = HttpSyncGraphQlClient.builder(builder.build()).url("http://localhost:8095/api/graphql").build();
    }

    @GetMapping("/people/{id}")
    PersonView person(@PathVariable long id) {
        return graphQl.document("query person($id: ID!) { person(id: $id) { name salary } }")
                .variable("id", id)
                .retrieveSync("person")
                .toEntity(PersonView.class);
    }

    /**
     * The document is the resource graphql-documents/rename.graphql; the response key is an alias.
     */
    @PostMapping("/people/{id}/name")
    PersonView rename(@PathVariable long id, @RequestBody String name) {
        return graphQl.documentName("rename").variable("id", id).variable("name", name)
                .retrieveSync("renamed")
                .toEntity(PersonView.class);
    }
}

@RestController
class EveryoneController {

    private final HttpGraphQlClient graphQl;

    EveryoneController(HttpGraphQlClient graphQl) {
        this.graphQl = graphQl;
    }

    @GetMapping("/everyone")
    Mono<List<PersonView>> everyone() {
        return graphQl.document("""
                # Everyone, by an alias
                {
                  all: everyone { name }
                }
                """).retrieve("all").toEntityList(PersonView.class);
    }
}
