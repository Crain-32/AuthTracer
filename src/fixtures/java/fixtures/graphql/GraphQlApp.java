package fixtures.graphql;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.BatchMapping;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;

@Configuration
@EnableMethodSecurity
@EnableAsync
class GraphQlApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests
                .requestMatchers("/api/graphql").hasAuthority("SCOPE_graphql")
                .anyRequest().denyAll());
        return http.build();
    }
}

record Person(long id, String name, BigDecimal salary) {
}

record Team(String name, String budget) {
}

@Service
class PersonService {

    @PreAuthorize("hasRole('READER')")
    public Person find(long id) {
        return new Person(id, "ann", BigDecimal.TEN);
    }

    @PreAuthorize("hasRole('READER')")
    public List<Person> all() {
        return List.of(find(1));
    }
}

/**
 * Runs on another thread, without the caller's security context: its check fails there, not for the caller.
 */
@Service
class BadgeAudit {

    @Async
    @PreAuthorize("isAuthenticated()")
    public void record(long id) {
    }
}

@Controller
class PersonGraphController {

    private final PersonService people;
    private final BadgeAudit audit;

    PersonGraphController(PersonService people, BadgeAudit audit) {
        this.people = people;
        this.audit = audit;
    }

    @SchemaMapping(typeName = "Person", field = "badge")
    String badge(Person person) {
        audit.record(person.id());
        return "badge";
    }

    @QueryMapping
    Person person(@Argument long id) {
        return people.find(id);
    }

    @QueryMapping(name = "everyone")
    List<Person> all() {
        return people.all();
    }

    @MutationMapping
    @PreAuthorize("hasRole('ADMIN')")
    Person rename(@Argument long id, @Argument String name) {
        return new Person(id, name, BigDecimal.ONE);
    }

    /**
     * A field of the Person type, not an operation: the service's check guards it.
     */
    @SchemaMapping(typeName = "Person", field = "manager")
    Person manager(Person person) {
        return people.find(1);
    }

    /**
     * Resolves a property Person already has, with a check of its own.
     */
    @SchemaMapping(typeName = "Person", field = "salary")
    @PreAuthorize("hasRole('HR')")
    BigDecimal salary(Person person) {
        return person.salary();
    }

    /**
     * The type is named after the source parameter's class.
     */
    @SchemaMapping
    String nickname(@Argument String style, Person person) {
        return person.name();
    }

    @BatchMapping
    @PreAuthorize("hasRole('TEAMS')")
    Map<Person, Team> team(List<Person> people) {
        return Map.of();
    }
}

/**
 * Class-level type name: every @SchemaMapping method below is a Query field.
 */
@Controller
@SchemaMapping(typeName = "Query")
class VersionGraphController {

    @SchemaMapping
    String version() {
        return "1";
    }
}
