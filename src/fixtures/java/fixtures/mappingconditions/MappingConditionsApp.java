package fixtures.mappingconditions;

import java.util.List;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Handlers of one path and method told apart by a header, the request's media type, or the API version.
 */
@SpringBootApplication
@EnableMethodSecurity
class MappingConditionsApp {
}

record User(Long id, String name) {
}

record UserV2(Long id, String name, String email) {
}

@RestController
@RequestMapping("/users")
class UserController {

    @GetMapping(headers = "X-API-VERSION=1")
    List<User> usersV1() {
        return List.of();
    }

    @GetMapping(headers = "X-API-VERSION=2")
    @PreAuthorize("hasRole('ADMIN')")
    List<UserV2> usersV2() {
        return List.of();
    }

    @PostMapping(consumes = "application/json")
    User create(@RequestBody User user) {
        return user;
    }

    @PostMapping(consumes = "text/csv")
    @PreAuthorize("hasRole('IMPORTER')")
    List<User> importCsv(@RequestBody String csv) {
        return List.of();
    }

    @GetMapping(path = "/{id}", produces = "application/json")
    User user(@PathVariable Long id) {
        return new User(id, "name");
    }

    @GetMapping(path = "/me", version = "1.0")
    User me() {
        return new User(1L, "me");
    }

    @GetMapping(path = "/me", version = "2.0")
    UserV2 meV2() {
        return new UserV2(1L, "me", "me@example.com");
    }
}
