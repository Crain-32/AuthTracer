package fixtures.graphqlclientforms;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.graphql.client.ClientGraphQlResponse;
import org.springframework.graphql.client.HttpSyncGraphQlClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Spring for GraphQL's client, the other ways requests are written: on a RestClient with the URL, executed rather
 * than retrieved, a document name with no document, a document AuthTracer can't read, with and without a response
 * path.
 */
record Person(String name) {
}

@Component
class PeopleClient {

    private final HttpSyncGraphQlClient graphQl = HttpSyncGraphQlClient
            .create(RestClient.create("http://people:8095/graphql"));

    String person(long id) {
        ClientGraphQlResponse response = graphQl.document("query { person(id: 1) { name } }").variable("id", id)
                .executeSync();
        return response.field("person.name").toEntity(String.class);
    }

    List<Person> everyone() {
        return graphQl.documentName("everyone").retrieveSync("people").toEntityList(Person.class);
    }

    String named(String document) {
        return graphQl.document(document).retrieveSync("person.name").toEntity(String.class);
    }

    ClientGraphQlResponse raw(String document) {
        return graphQl.document(document).executeSync();
    }
}

/**
 * The endpoint's URL joined from a configured base and its path.
 */
@Component
class TeamsClient {

    private final HttpSyncGraphQlClient graphQl;

    TeamsClient(RestClient.Builder builder, @Value("${teams.base-url}") String baseUrl) {
        this.graphQl = HttpSyncGraphQlClient.builder(builder.build()).url(baseUrl + "/graphql").build();
    }

    String team(long id) {
        return graphQl.document("query team($id: ID!) { team(id: $id) { name } }").variable("id", id)
                .retrieveSync("team.name").toEntity(String.class);
    }
}

@RestController
class PeopleController {

    private final PeopleClient people;
    private final TeamsClient teams;

    PeopleController(PeopleClient people, TeamsClient teams) {
        this.people = people;
        this.teams = teams;
    }

    @GetMapping("/teams/{id}")
    String team(@PathVariable long id) {
        return teams.team(id);
    }

    @GetMapping("/people/{id}")
    String person(@PathVariable long id) {
        return people.person(id);
    }

    @GetMapping("/people")
    List<Person> everyone() {
        return people.everyone();
    }

    @GetMapping("/query")
    String query(@RequestParam String document) {
        return people.named(document) + people.raw(document);
    }
}
