package fixtures.inheritedmappings;

import java.util.List;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mappings a controller inherits, as Spring's findMergedAnnotation finds them: from the interface it implements, as
 * OpenAPI Generator writes one, and from an abstract base controller.
 */
@SpringBootApplication
@EnableMethodSecurity
class InheritedMappingsApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/users/**").hasRole("USERS")
                .requestMatchers("/public/**", "/admin/**", "/accounts/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@RequestMapping("/users")
interface UsersApi {

    @GetMapping("/{id}")
    String user(@PathVariable String id);

    @PostMapping
    default String create(@RequestBody String user) {
        return user;
    }
}

@RestController
class UsersController implements UsersApi {

    @Override
    public String user(String id) {
        return id;
    }
}

abstract class CrudController {

    @GetMapping
    public List<String> list() {
        return List.of();
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
    }
}

@RestController
@RequestMapping("/orders")
class OrdersController extends CrudController {

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public void delete(String id) {
    }
}

/**
 * A generic base: javac gives the subclass a bridge, create(Object), besides its override.
 */
abstract class GenericCrudController<T> {

    @PostMapping
    public T create(@RequestBody T body) {
        return body;
    }
}

record Account(String name) {
}

@RestController
@RequestMapping("/accounts")
class AccountsController extends GenericCrudController<Account> {

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public Account create(Account account) {
        return account;
    }
}

@Component
class Guard {

    @PreAuthorize("hasRole('ADMIN')")
    public void admin(String id) {
    }
}

/**
 * The handler is the base class's; the check it calls on this is each controller's own.
 */
abstract class DocsController {

    @GetMapping("/{id}")
    public String get(@PathVariable String id) {
        check(id);
        return "doc";
    }

    abstract void check(String id);
}

@RestController
@RequestMapping("/admin/docs")
class AdminDocsController extends DocsController {

    private final Guard guard;

    AdminDocsController(Guard guard) {
        this.guard = guard;
    }

    @Override
    void check(String id) {
        guard.admin(id);
    }
}

@RestController
@RequestMapping("/public/docs")
class PublicDocsController extends DocsController {

    @Override
    void check(String id) {
    }
}
