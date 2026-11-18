package fixtures.datarestimport;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.rest.core.annotation.HandleBeforeSave;
import org.springframework.data.rest.core.annotation.RepositoryEventHandler;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.data.rest.webmvc.config.RepositoryRestMvcConfiguration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

/**
 * Spring Data REST without Spring Boot: imported, with repositories built on a generic base repository, a search
 * method at a path of its own, a default method, an item whose lookup isn't exported, and an event handler for the
 * entities' common base class.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Import(RepositoryRestMvcConfiguration.class)
class DataRestImportConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("API"));
        return http.build();
    }
}

interface Owned {

    String getOwner();
}

abstract class AuditedEntity implements Owned {

    private Long id;
    private String owner;

    public Long getId() {
        return id;
    }

    @Override
    public String getOwner() {
        return owner;
    }
}

class Customer extends AuditedEntity {

    private String name;

    public String getName() {
        return name;
    }
}

class Invoice extends AuditedEntity {

    private String number;

    public String getNumber() {
        return number;
    }
}

/**
 * Not exported, whatever its repository says: the domain type says so.
 */
@RestResource(exported = false)
class Ledger {

    private Long id;

    public Long getId() {
        return id;
    }
}

@Component
@RepositoryEventHandler
class AuditHandler {

    @HandleBeforeSave
    @PreAuthorize("hasRole('AUDITED')")
    public void beforeSave(AuditedEntity entity) {
    }

    @HandleBeforeSave
    @PreAuthorize("hasRole('OWNER')")
    public void beforeSaveOwned(Owned owned) {
    }
}
