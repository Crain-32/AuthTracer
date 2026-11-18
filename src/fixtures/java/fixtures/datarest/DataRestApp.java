package fixtures.datarest;

import java.util.List;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.Repository;
import org.springframework.data.rest.core.annotation.HandleAfterDelete;
import org.springframework.data.rest.core.annotation.HandleBeforeCreate;
import org.springframework.data.rest.core.annotation.HandleBeforeSave;
import org.springframework.data.rest.core.annotation.RepositoryEventHandler;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

/**
 * Spring Data REST: repositories exported as HTTP resources, with no controller.
 */
@SpringBootApplication
@EnableMethodSecurity
class DataRestApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

class AuditEntry {

    private Long id;
    private String action;

    public Long getId() {
        return id;
    }

    public String getAction() {
        return action;
    }
}

class Secret {

    private Long id;

    public Long getId() {
        return id;
    }
}

/**
 * Not public, but annotated as exported: exported at its own path.
 */
@RepositoryRestResource(path = "audit")
interface AuditRepository extends Repository<AuditEntry, Long> {

    List<AuditEntry> findAll();
}

/**
 * Not public and not annotated: not exported.
 */
interface InternalRepository extends CrudRepository<Secret, Long> {
}

/**
 * Runs inside Spring Data REST's requests: before a person is created, and after one is deleted.
 */
@Component
@RepositoryEventHandler
class PersonEvents {

    @HandleBeforeCreate
    @PreAuthorize("hasRole('REGISTRAR')")
    public void beforeCreate(Person person) {
    }

    @HandleAfterDelete
    @PreAuthorize("hasRole('ARCHIVIST')")
    public void afterDelete(Object deleted) {
    }

    @HandleBeforeSave
    public void beforeSaveSecret(Secret secret) {
    }
}

class Note {

    private Long id;
    private String text;

    public Long getId() {
        return id;
    }

    public String getText() {
        return text;
    }
}
